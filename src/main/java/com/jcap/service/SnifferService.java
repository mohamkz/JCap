package com.jcap.service;

import com.jcap.model.PacketModel;
import javafx.application.Platform;
import javafx.concurrent.Service;
import javafx.concurrent.Task;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.*;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IcmpV6Type;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SnifferService extends Service<Void> {

    private static final Logger logger = LoggerFactory.getLogger(SnifferService.class);

    private PcapHandle handle;
    private final PcapNetworkInterface nif;
    private final Consumer<PacketModel> onPacketCaptured;
    private final Consumer<String> onError;
    private long startNano = 0;

    public SnifferService(PcapNetworkInterface nif, Consumer<PacketModel> callback, Consumer<String> onError) {
        this.nif = nif;
        this.onPacketCaptured = callback;
        this.onError = onError;
    }

    @Override
    protected Task<Void> createTask() {
        return new Task<>() {
            @Override
            protected Void call() {
                int snapLen = 65536; // in bytes
                int readTimeout = 10; // in milliseconds

                try {
                    handle = nif.openLive(snapLen, PromiscuousMode.PROMISCUOUS, readTimeout);
                }
                catch (PcapNativeException e) {
                    logger.error("Failed to open device {}. {}", nif.getName(), e.getMessage());

                    Platform.runLater(() -> onError.accept("Error opening device: Access Denied."));
                    return null;
                }

                PacketListener listener = getPacketListener();

                try {
                    logger.info("Starting packet capture loop on {}", nif.getName());
                    handle.loop(-1, listener);
                } catch (InterruptedException e) {
                    logger.info("Capture loop interrupted (Stop requested).");
                }
                catch (PcapNativeException | NotOpenException e) {
                    logger.error("Critical error during packet capture loop.", e);
                    Platform.runLater(() -> onError.accept("Capture Error: " + e.getMessage()));
                }
                finally {
                    if (handle != null && handle.isOpen()) {
                        handle.close();
                        logger.info("Pcap handle closed successfully.");
                    }
                }
                return null;
            }

            private PacketListener getPacketListener() {
                AtomicInteger packetCounter = new AtomicInteger(1);

                return packet -> {
                    long currentNano = System.nanoTime();

                    if (startNano == 0) {
                        startNano = currentNano;
                    }

                    double relativeTime = (currentNano - startNano) / 1_000_000_000.0;

                    String src = "Unknown";
                    String dst = "Unknown";
                    String proto = "Unknown";

                    if (packet.contains(IpV4Packet.class)) {
                        IpV4Packet ip4 = packet.get(IpV4Packet.class);
                        src = ip4.getHeader().getSrcAddr().getHostAddress();
                        dst = ip4.getHeader().getDstAddr().getHostAddress();
                        proto = ip4.getHeader().getProtocol().name();
                    }
                    else if (packet.contains(IpV6Packet.class)) {
                        IpV6Packet ip6 = packet.get(IpV6Packet.class);
                        src = ip6.getHeader().getSrcAddr().getHostAddress();
                        dst = ip6.getHeader().getDstAddr().getHostAddress();
                        proto = ip6.getHeader().getNextHeader().name();
                    }
                    else if (packet.contains(ArpPacket.class)) {
                        ArpPacket arp = packet.get(ArpPacket.class);
                        src = arp.getHeader().getSrcHardwareAddr().toString();
                        dst = arp.getHeader().getDstHardwareAddr().toString();
                        proto = "ARP";
                    }
                    else if (packet.contains(EthernetPacket.class)) {
                        EthernetPacket eth = packet.get(EthernetPacket.class);
                        src = eth.getHeader().getSrcAddr().toString();
                        dst = eth.getHeader().getDstAddr().toString();
                        proto = "ETHERNET";
                    }

                    String infoStr = getInfoString(packet);

                    if (!proto.equals("Unknown")) {
                        PacketModel model = new PacketModel(
                                packetCounter.getAndIncrement(),
                                String.format("%.6f", relativeTime),
                                src,
                                dst,
                                proto,
                                packet.length(),
                                infoStr,
                                packet.getRawData()
                        );
                        Platform.runLater(() -> onPacketCaptured.accept(model));
                    }
                };
            }
        };
    }

    public String getInfoString(Packet packet) {
        StringBuilder info = new StringBuilder();

        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcp = packet.get(TcpPacket.class);
            List<String> flags = new ArrayList<>();

            if (tcp.getHeader().getSyn()) flags.add("SYN");
            if (tcp.getHeader().getAck()) flags.add("ACK");
            if (tcp.getHeader().getRst()) flags.add("RST");
            if (tcp.getHeader().getFin()) flags.add("FIN");
            if (tcp.getHeader().getPsh()) flags.add("PSH");
            if (tcp.getHeader().getUrg()) flags.add("URG");

            info.append(tcp.getHeader().getSrcPort().valueAsInt()).append(" → ").append(tcp.getHeader().getDstPort().valueAsInt());

            info.append("  [").append(String.join(", ", flags)).append("]");

            info.append("  Seq=").append(tcp.getHeader().getSequenceNumberAsLong());
            info.append("  Ack=").append(tcp.getHeader().getAcknowledgmentNumberAsLong());
            info.append("  Win=").append(tcp.getHeader().getWindowAsInt());

            if (tcp.getPayload() != null && (tcp.getHeader().getDstPort().valueAsInt() == 80)) {
                String payloadStr = new String(tcp.getPayload().getRawData());
                int firstLineEnd = payloadStr.indexOf("\r\n");
                if (firstLineEnd > 0) {
                    payloadStr = payloadStr.substring(0, firstLineEnd);
                    info.append("  [").append(payloadStr).append("]");
                }
            }
        }
        else if (packet.contains(UdpPacket.class)) {
            UdpPacket udp = packet.get(UdpPacket.class);

            info.append(udp.getHeader().getSrcPort().valueAsInt()).append(" → ").append(udp.getHeader().getDstPort().valueAsInt());

            info.append("  Len=").append(udp.getHeader().getLength());

            if (udp.getHeader().getSrcPort().valueAsInt() == 53 || udp.getHeader().getDstPort().valueAsInt() == 53) {
                info.append("  (DNS Query/Response)");
            }
        }
        else if (packet.contains(ArpPacket.class)) {
            ArpPacket arp = packet.get(ArpPacket.class);
            ArpOperation op = arp.getHeader().getOperation();

            if (op.equals(ArpOperation.REQUEST)) {
                info.append("Who has ").append(arp.getHeader().getDstProtocolAddr().getHostAddress())
                        .append("? Tell ").append(arp.getHeader().getSrcProtocolAddr().getHostAddress());
            }
            else if (op.equals(ArpOperation.REPLY)) {
                info.append(arp.getHeader().getSrcProtocolAddr().getHostAddress()).append(" is at ")
                        .append(arp.getHeader().getSrcHardwareAddr());
            }
            else {
                info.append(op.name());
            }
        }
        else if (packet.contains(IcmpV4CommonPacket.class)) {
            IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);

            if (icmp.getHeader().getType().equals(IcmpV4Type.ECHO)) {
                info.append("Echo (Ping) Request");
            } else if (icmp.getHeader().getType().equals(IcmpV4Type.ECHO_REPLY)) {
                info.append("Echo (Ping) Reply");
            } else {
                info.append(icmp.getHeader().getType().name());
            }
        }
        else if (packet.contains(IcmpV6CommonPacket.class)) {
            IcmpV6CommonPacket icmp6 = packet.get(IcmpV6CommonPacket.class);
            IcmpV6Type type = icmp6.getHeader().getType();

            if (type.equals(IcmpV6Type.ECHO_REQUEST)) {
                info.append("Echo (Ping6) Request");
            }
            else if (type.equals(IcmpV6Type.ECHO_REPLY)) {
                info.append("Echo (Ping6) Reply");
            }
            else if (type.equals(IcmpV6Type.NEIGHBOR_SOLICITATION)) {
                info.append("Neighbor Solicitation");
            }
            else if (type.equals(IcmpV6Type.NEIGHBOR_ADVERTISEMENT)) {
                info.append("Neighbor Advertisement");
            }
            else if (type.equals(IcmpV6Type.ROUTER_SOLICITATION)) {
                info.append("Router Solicitation");
            }
            else if (type.equals(IcmpV6Type.ROUTER_ADVERTISEMENT)) {
                info.append("Router Advertisement");
            }
            else {
                info.append(type.name());
            }
        }

        return info.toString();
    }

    @Override
    public boolean cancel() {
        if (handle != null && handle.isOpen()) {
            try {
                handle.breakLoop();
                logger.info("Requested loop break...");
            } catch (NotOpenException e) {
                logger.error("Failed to close Pcap handle. {}", e.getMessage());
            }
        }
        return super.cancel();
    }
}
