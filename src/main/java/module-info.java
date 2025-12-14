module com.jcap {
    requires javafx.controls;
    requires javafx.fxml;
    requires atlantafx.base;
    requires org.pcap4j.core;

    opens com.jcap.controller to javafx.fxml;
    opens com.jcap.model to javafx.base;

    exports com.jcap;
}