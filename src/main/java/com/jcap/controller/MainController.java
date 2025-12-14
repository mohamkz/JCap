package com.jcap.controller;

import com.jcap.model.PacketModel;
import com.jcap.service.SnifferService;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MainController {

    private static final Logger logger = LoggerFactory.getLogger(MainController.class);

    @FXML private ComboBox<String> deviceCombo;
    @FXML private Button startBtn;
    @FXML private Button stopBtn;

    @FXML private TextField filterField;

    @FXML private TableView<PacketModel> table;

    @FXML private TableColumn<PacketModel, Integer> colNo;
    @FXML private TableColumn<PacketModel, Double> colTime;
    @FXML private TableColumn<PacketModel, String> colSrc;
    @FXML private TableColumn<PacketModel, String> colDst;
    @FXML private TableColumn<PacketModel, String> colProto;
    @FXML private TableColumn<PacketModel, Integer> colLen;

    @FXML private TextArea hexDump;

    private List<PcapNetworkInterface> interfaces;
    private SnifferService service;

    @FXML
    public void initialize() {
        colNo.setCellValueFactory(new PropertyValueFactory<>("Number"));
        colTime.setCellValueFactory(new PropertyValueFactory<>("Timestamp"));
        colSrc.setCellValueFactory(new PropertyValueFactory<>("Source"));
        colDst.setCellValueFactory(new PropertyValueFactory<>("Destination"));
        colProto.setCellValueFactory(new PropertyValueFactory<>("Protocol"));
        colLen.setCellValueFactory(new PropertyValueFactory<>("Length"));

        hexDump.setStyle("-fx-font-family: 'Monospaced'; -fx-font-size: 16;");

        table.setRowFactory(tv -> {
            TableRow<PacketModel> row = new TableRow<PacketModel>() {
                @Override
                protected void updateItem(PacketModel item, boolean empty) {
                    super.updateItem(item, empty);
                    styleRow(this);
                }
            };

            row.selectedProperty().addListener((obs, wasSelected, isSelected) -> styleRow(row));

            return row;
        });

        try {
            logger.info("Scanning for network interfaces...");
            interfaces = Pcaps.findAllDevs();

            if (interfaces == null || interfaces.isEmpty()) {
                logger.warn("No network interfaces found. Ensure you have admin/root privileges.");
            } else {
                for (PcapNetworkInterface dev : interfaces) {
                    String desc = (dev.getDescription() != null) ? dev.getDescription() : dev.getName();
                    deviceCombo.getItems().add(desc);
                }
                deviceCombo.getSelectionModel().select(0);
                logger.info("Loaded {} interfaces.", interfaces.size());
            }
        }
        catch (PcapNativeException e) {
            logger.error("Failed to load network interfaces. Is Npcap/Libpcap installed?", e);
        }

        table.getSelectionModel().selectedItemProperty().addListener((obs, oldSelection, newSelection) -> {
            if (newSelection != null) hexDump.setText(formatHex(newSelection.getPayload()));
        });
    }

    @FXML
    private void onStart() {
        int index = deviceCombo.getSelectionModel().getSelectedIndex();
        if (index < 0) return;

        table.getItems().clear();
        String filterText = filterField.getText().trim();

        service = new SnifferService(
                interfaces.get(index),
                filterText,
                packet -> table.getItems().add(packet),
                errorMessage -> {
                    showAlert(errorMessage);
                    onStop();
                    filterField.clear();
                }
        );
        service.start();

        deviceCombo.setDisable(true);
        filterField.setDisable(true);

        startBtn.setDisable(true);
        stopBtn.setDisable(false);
    }

    @FXML void onStop() {
        if (service != null) service.cancel();

        hexDump.clear();

        deviceCombo.setDisable(false);
        filterField.setDisable(false);

        startBtn.setDisable(false);
        stopBtn.setDisable(true);
    }

    private void styleRow(TableRow<PacketModel> row) {
        if (row.isSelected()) {
            row.setStyle("-fx-background-color: #2C3E50; -fx-text-fill: white;");
            return;
        }

        if (row.isEmpty() || row.getItem() == null) {
            row.setStyle("");
            return;
        }

        String proto = row.getItem().getProtocol().toUpperCase();
        String style = "-fx-text-fill: black; -fx-background-color: ";

        if (proto.contains("TCP")) {
            row.setStyle(style + "rgba(50, 205, 50, 0.15);");
        }
        else if (proto.contains("UDP")) {
            row.setStyle(style + "rgba(30, 144, 255, 0.15);");
        }
        else if (proto.contains("ARP")) {
            row.setStyle(style + "rgba(255, 165, 0, 0.15);");
        }
        else if (proto.contains("ICMP")) {
            row.setStyle(style + "rgba(255, 105, 180, 0.15);");
        }
        else if (proto.contains("IGMP")) {
            row.setStyle(style + "rgba(200, 100, 200, 0.15);");
        }
        else {
            row.setStyle(style + "rgba(128, 128, 128, 0.15);");
        }
    }

    private void showAlert(String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    private String formatHex(byte[] data) {
        if (data == null || data.length == 0) return "";

        StringBuilder sb = new StringBuilder();

        // iterate in chunks of 16 bytes
        for (int i = 0; i < data.length; i += 16) {
            // offset
            sb.append(String.format("%04X   ", i));

            StringBuilder hexPart = new StringBuilder();
            StringBuilder textPart = new StringBuilder();

            for (int j = 0; j < 16; j++) {
                if (i + j < data.length) {
                    byte b = data[i + j];

                    hexPart.append(String.format("%02X ", b));

                    if (b >= 32 && b <= 126) {
                        textPart.append((char) b);
                    } else {
                        textPart.append(".");
                    }
                }
                else {
                    hexPart.append("   ");
                }
            }
            sb.append(hexPart);
            sb.append("   ");
            sb.append(textPart);
            sb.append("\n");
        }
        return sb.toString();
    }
}
