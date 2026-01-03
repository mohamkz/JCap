package com.jcap.model;

import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleStringProperty;

public class PacketModel {

    private final SimpleIntegerProperty number;
    private final SimpleStringProperty timestamp;
    private final SimpleStringProperty source;
    private final SimpleStringProperty destination;
    private final SimpleStringProperty protocol;
    private final SimpleIntegerProperty length;
    private final SimpleStringProperty info;
    private final byte[] payload;

    public PacketModel(int num, String timestamp, String src, String dst,
                       String proto, int len, String info, byte[] data) {
        this.number = new SimpleIntegerProperty(num);
        this.timestamp = new SimpleStringProperty(timestamp);
        this.source = new SimpleStringProperty(src);
        this.destination = new SimpleStringProperty(dst);
        this.protocol = new SimpleStringProperty(proto);
        this.length = new SimpleIntegerProperty(len);
        this.info = new SimpleStringProperty(info);
        this.payload = data;
    }

    public int getNumber() { return number.get(); }
    public String getTimestamp() { return timestamp.get(); }
    public String getSource() { return source.get(); }
    public String getDestination() { return destination.get(); }
    public String getProtocol() { return protocol.get(); }
    public int getLength() { return length.get(); }
    public byte[] getPayload() { return payload.clone(); }
    public String getInfo() { return info.get(); }

    public SimpleIntegerProperty numberProperty() { return number; }
    public SimpleStringProperty timestampProperty() { return timestamp; }
    public SimpleStringProperty sourceProperty() { return source; }
    public SimpleStringProperty destinationProperty() { return destination; }
    public SimpleStringProperty protocolProperty() { return protocol; }
    public SimpleIntegerProperty lengthProperty() { return length; }
    public SimpleStringProperty infoProperty() { return info; }
}
