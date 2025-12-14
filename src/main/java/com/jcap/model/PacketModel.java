package com.jcap.model;

public class PacketModel {
    private final Integer number;
    private final String timestamp;
    private final String source;
    private final String destination;
    private final String protocol;
    private final Integer length;
    private final byte[] payload;

    public PacketModel(int num, String timestamp, String src, String dst, String proto, int len, byte[] data) {
        this.number = num;
        this.timestamp = timestamp;
        this.source = src;
        this.destination = dst;
        this.protocol = proto;
        this.length = len;
        this.payload = data;
    }

    public int getNumber() { return number; }
    public String getTimestamp() { return timestamp; }
    public String getSource() { return source; }
    public String getDestination() { return destination; }
    public String getProtocol() { return protocol; }
    public int getLength() { return length; }
    public byte[] getPayload() { return payload; }
}
