package com.jcap.service;

import com.jcap.model.PacketModel;
import javafx.application.Platform;
import javafx.concurrent.Service;
import javafx.concurrent.Task;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SnifferService extends Service<Void> {

    private static final Logger logger = LoggerFactory.getLogger(SnifferService.class);

    private PcapHandle handle;
    private final PcapNetworkInterface nif;
    private final Consumer<PacketModel> onPacketCaptured;
    private final Consumer<String> onError;
    private final String filter;
    private long startTime = 0;

    public SnifferService(PcapNetworkInterface nif, String filter, Consumer<PacketModel> callback, Consumer<String> onError) {
        this.nif = nif;
        this.filter = filter;
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

                if (filter != null && !filter.isEmpty()) {
                    try {
                        handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
                        logger.info("Filter applied: {}", filter);
                    }
                    catch (PcapNativeException | NullPointerException | NotOpenException e) {
                        logger.error("Invalid Filter Syntax: {}.", filter);

                        Platform.runLater(() -> onError.accept("Invalid Filter Syntax: " + filter));

                        if (handle != null && handle.isOpen()) {
                            handle.close();
                        }
                        return null;
                    }
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
                return null;
            }

            private PacketListener getPacketListener() {
                AtomicInteger packetCounter = new AtomicInteger(1);

                return packet -> {
                    long currentMicros = System.currentTimeMillis() * 1000;

                    if (startTime == 0) startTime = currentMicros;

                    double relativeTime = (currentMicros - startTime) / 1_000_000.0;

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

                    if (!proto.equals("Unknown")) {
                        PacketModel model = new PacketModel(
                                packetCounter.getAndIncrement(),
                                String.format("%.6f", relativeTime),
                                src,
                                dst,
                                proto,
                                packet.length(),
                                packet.getRawData()
                        );
                        Platform.runLater(() -> onPacketCaptured.accept(model));
                    }
                };
            }
        };
    }

    @Override
    public boolean cancel() {
        if (handle != null && handle.isOpen()) {
            try {
                handle.breakLoop();
                handle.close();
                logger.info("Pcap handle closed successfully.");
            } catch (NotOpenException e) {
                logger.error("Failed to close Pcap handle. {}", e.getMessage());
            }
        }
        return super.cancel();
    }
}
