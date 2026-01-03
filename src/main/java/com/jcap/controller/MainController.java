package com.jcap.controller;

import com.jcap.model.PacketModel;
import com.jcap.service.DatabaseService;
import com.jcap.service.SnifferService;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.paint.Color;
import javafx.scene.shape.Rectangle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.util.List;
import java.util.Optional;

import org.pcap4j.packet.*;
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
    @FXML private TableColumn<PacketModel, String> colInfo;

    @FXML TreeView<String> packetTree;
    @FXML TextArea hexDump;

    private List<PcapNetworkInterface> interfaces;
    private SnifferService service;
    private final ObservableList<PacketModel> masterList = FXCollections.observableArrayList();
    private FilteredList<PacketModel> filteredList;

    @FXML
    public void initialize() {
        DatabaseService.initialize();

        setupTableColumns();

        setupUIStyling();

        setupSearchFilter();

        table.getSelectionModel().selectedItemProperty().addListener((obs, oldSelection, newSelection) -> {
            if (newSelection != null) {
                buildPacketTree(newSelection.getPayload());
                hexDump.setText(formatHex(newSelection.getPayload()));
            }
            else {
                hexDump.clear();
                packetTree.setRoot(null);
            }
        });

        loadNetworkInterfaces();
    }

    private void setupTableColumns() {
        colNo.setCellValueFactory(new PropertyValueFactory<>("Number"));
        colTime.setCellValueFactory(new PropertyValueFactory<>("Timestamp"));
        colSrc.setCellValueFactory(new PropertyValueFactory<>("Source"));
        colDst.setCellValueFactory(new PropertyValueFactory<>("Destination"));
        colProto.setCellValueFactory(new PropertyValueFactory<>("Protocol"));
        colLen.setCellValueFactory(new PropertyValueFactory<>("Length"));
        colInfo.setCellValueFactory(new PropertyValueFactory<>("Info"));

        filteredList = new FilteredList<>(masterList, p -> true);
        table.setItems(filteredList);
        table.setPlaceholder(new Label(""));

        table.setRowFactory(tv -> {
            TableRow<PacketModel> row = new TableRow<>() {
                @Override
                protected void updateItem(PacketModel item, boolean empty) {
                    super.updateItem(item, empty);
                    styleRow(this);
                }
            };

            row.selectedProperty().addListener((obs, wasSelected, isSelected) -> styleRow(row));
            return row;
        });
    }

    private void setupUIStyling() {
        Rectangle startSquare = new Rectangle(18, 18, Color.web("#2ea043"));
        startSquare.setArcWidth(4);
        startSquare.setArcHeight(4);
        startBtn.setGraphic(startSquare);
        startBtn.setOnMouseEntered(e -> startBtn.setStyle(getButtonStyle(true)));
        startBtn.setOnMouseExited(e -> startBtn.setStyle(getButtonStyle(false)));


        Rectangle stopSquare = new Rectangle(18, 18, Color.web("#d1242f"));
        stopSquare.setArcWidth(4);
        stopSquare.setArcHeight(4);
        stopBtn.setGraphic(stopSquare);
        stopBtn.setOnMouseEntered(e -> stopBtn.setStyle(getButtonStyle(true)));
        stopBtn.setOnMouseExited(e -> stopBtn.setStyle(getButtonStyle(false)));

        hexDump.setStyle("-fx-font-family: 'Monospaced'; -fx-font-size: 16;");
    }

    private String getButtonStyle(boolean hover) {
        if (hover) {
            return "-fx-background-color: #f6f8fa; -fx-border-color: #b0b8c0; -fx-border-radius: 4; -fx-padding: 3; -fx-cursor: hand;";
        }
        return "-fx-background-color: white; -fx-border-color: #d0d7de; -fx-border-radius: 4; -fx-padding: 3; -fx-cursor: hand;";
    }

    private void loadNetworkInterfaces() {
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
            logger.error("Failed to load network interfaces. {}", e.getMessage());
        }
    }

    @FXML
    private void onStart() {
        int index = deviceCombo.getSelectionModel().getSelectedIndex();
        if (index < 0) return;

        masterList.clear();
        hexDump.clear();

        service = new SnifferService(
                interfaces.get(index),
                masterList::add,
                errorMessage -> {
                    showAlert(errorMessage);
                    onStop();
                    filterField.clear();
                }
        );
        service.start();

        deviceCombo.setDisable(true);

        startBtn.setDisable(true);
        stopBtn.setDisable(false);
    }

    @FXML void onStop() {
        if (service != null) service.cancel();

        deviceCombo.setDisable(false);

        startBtn.setDisable(false);
        stopBtn.setDisable(true);
    }

    @FXML
    private void onSaveCapture() {
        if (masterList.isEmpty()) {
            showAlert("Nothing to save!");
            return;
        }

        onStop();

        TextInputDialog dialog = new TextInputDialog("Capture_" + System.currentTimeMillis());
        dialog.setTitle("Save Capture");
        dialog.setHeaderText(null);
        dialog.setContentText("Enter a name for this capture:");

        Optional<String> result = dialog.showAndWait();
        result.ifPresent(name -> {
            if (name.trim().isEmpty()) {
                showAlert("Name cannot be empty.");
                return;
            }

            Task<Boolean> saveTask = DatabaseService.saveCapture(name, masterList);

            saveTask.setOnSucceeded(e -> {
                table.setDisable(false);
            });

            saveTask.setOnFailed(e -> {
                Throwable error = saveTask.getException();
                showAlert("Database Error: " + error.getMessage());
                table.setDisable(false);
            });

            table.setDisable(true);
            new Thread(saveTask).start();
        });
    }

    @FXML
    private void onLoadCapture() {
        List<String> sessions = DatabaseService.getCaptureNames();

        if (sessions.isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("Load Capture");
            alert.setHeaderText(null);
            alert.setContentText("No saved captures found.");
            alert.showAndWait();
            return;
        }

        ChoiceDialog<String> dialog = new ChoiceDialog<>(sessions.getFirst(), sessions);
        dialog.setTitle("Open Capture");
        dialog.setHeaderText(null);
        dialog.setContentText("Capture Name:");

        Optional<String> result = dialog.showAndWait();
        result.ifPresent(name -> {
            onStop();

            masterList.clear();
            packetTree.setRoot(null);
            hexDump.clear();

            List<PacketModel> loadedPackets = DatabaseService.loadCapture(name);
            masterList.addAll(loadedPackets);

            table.refresh();
        });
    }

    @FXML
    private void onDeleteCapture() {
        List<String> sessions = DatabaseService.getCaptureNames();
        if (sessions.isEmpty()) {
            showAlert("No saved captures to delete.");
            return;
        }

        ChoiceDialog<String> dialog = new ChoiceDialog<>(sessions.getFirst(), sessions);
        dialog.setTitle("Delete Capture");
        dialog.setHeaderText(null);
        dialog.setContentText("Select capture to delete:");

        Optional<String> result = dialog.showAndWait();
        result.ifPresent(name -> {

            Alert confirm = new Alert(Alert.AlertType.CONFIRMATION);
            confirm.setTitle("Confirm Delete");
            confirm.setHeaderText(null);
            confirm.setContentText("Are you sure you want to delete '" + name + "'?\nThis cannot be undone.");

            Optional<ButtonType> answer = confirm.showAndWait();
            if (answer.isPresent() && answer.get() == ButtonType.OK) {
                DatabaseService.deleteCapture(name);
            }
        });
    }

    @FXML void onExit() {
        Platform.exit();
        System.exit(0);
    }

    @FXML void onShowAbout() {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("About JCap");
        alert.setHeaderText("JCap Network Sniffer");
        alert.setContentText("A JavaFX based packet analyzer using Pcap4j.\n\nVersion: 1.0");
        alert.showAndWait();
    }

    private void buildPacketTree(byte[] data) {
        TreeItem<String> root = new TreeItem<>("Packet");
        packetTree.setRoot(root);

        if (data == null || data.length == 0) return;

        try {
            Packet current = EthernetPacket.newPacket(data, 0, data.length);

            while (current != null) {
                TreeItem<String> layerItem = null;

                switch (current) {
                    case EthernetPacket eth -> {
                        layerItem = new TreeItem<>("Ethernet II");
                        layerItem.getChildren().add(new TreeItem<>("Source:  " + eth.getHeader().getSrcAddr()));
                        layerItem.getChildren().add(new TreeItem<>("Destination:  " + eth.getHeader().getDstAddr()));
                        layerItem.getChildren().add(new TreeItem<>("Type:  " + eth.getHeader().getType()));
                    }
                    case IpV4Packet ip4 -> {
                        layerItem = new TreeItem<>("Internet Protocol Version 4");
                        layerItem.getChildren().add(new TreeItem<>("Source:  " + ip4.getHeader().getSrcAddr().getHostAddress()));
                        layerItem.getChildren().add(new TreeItem<>("Destination:  " + ip4.getHeader().getDstAddr().getHostAddress()));
                        layerItem.getChildren().add(new TreeItem<>("Protocol:  " + ip4.getHeader().getProtocol()));
                    }
                    case IpV6Packet ip6 -> {
                        layerItem = new TreeItem<>("Internet Protocol Version 6");
                        layerItem.getChildren().add(new TreeItem<>("Source:  " + ip6.getHeader().getSrcAddr().getHostAddress()));
                        layerItem.getChildren().add(new TreeItem<>("Destination:  " + ip6.getHeader().getDstAddr().getHostAddress()));
                    }
                    case TcpPacket tcp -> {
                        layerItem = new TreeItem<>("Transmission Control Protocol");
                        layerItem.getChildren().add(new TreeItem<>("Source Port:  " + tcp.getHeader().getSrcPort().valueAsInt()));
                        layerItem.getChildren().add(new TreeItem<>("Destination Port:  " + tcp.getHeader().getDstPort().valueAsInt()));
                        layerItem.getChildren().add(new TreeItem<>("Sequence:  " + tcp.getHeader().getSequenceNumberAsLong()));
                    }
                    case UdpPacket udp -> {
                        layerItem = new TreeItem<>("User Datagram Protocol");
                        layerItem.getChildren().add(new TreeItem<>("Source Port:  " + udp.getHeader().getSrcPort().valueAsInt()));
                        layerItem.getChildren().add(new TreeItem<>("Destination Port:  " + udp.getHeader().getDstPort().valueAsInt()));
                        layerItem.getChildren().add(new TreeItem<>("Length:  " + udp.getHeader().getLength()));
                    }
                    case ArpPacket arp -> {
                        layerItem = new TreeItem<>("Address Resolution Protocol");
                        layerItem.getChildren().add(new TreeItem<>("Operation Code:  " + arp.getHeader().getOperation()));
                        layerItem.getChildren().add(new TreeItem<>("Sender MAC:  " + arp.getHeader().getSrcHardwareAddr()));
                        layerItem.getChildren().add(new TreeItem<>("Sender IP:  " + arp.getHeader().getSrcProtocolAddr().getHostAddress()));
                        layerItem.getChildren().add(new TreeItem<>("Target MAC:  " + arp.getHeader().getDstHardwareAddr()));
                        layerItem.getChildren().add(new TreeItem<>("Target IP:  " + arp.getHeader().getDstProtocolAddr().getHostAddress()));
                    }
                    case IcmpV4CommonPacket icmp -> {
                        layerItem = new TreeItem<>("Internet Control Message Protocol");
                        layerItem.getChildren().add(new TreeItem<>("Type:  " + icmp.getHeader().getType()));
                        layerItem.getChildren().add(new TreeItem<>("Code:  " + icmp.getHeader().getCode()));
                        layerItem.getChildren().add(new TreeItem<>("Checksum:  " + icmp.getHeader().getChecksum()));
                    }
                    default -> {
                    }
                }

                if (layerItem != null) {
                    layerItem.setExpanded(true);
                    root.getChildren().add(layerItem);
                }
                current = current.getPayload();
            }
        } catch (Exception e) {
            root.getChildren().add(new TreeItem<>("Raw Data (Parsing Failed)"));
        }
    }

    private void styleRow(TableRow<PacketModel> row) {
        if (row.isSelected()) {
            row.setStyle("-fx-background-color: #0969da; -fx-text-fill: white; -color-fg-default: white;");
            return;
        }

        if (row.isEmpty() || row.getItem() == null) {
            row.setStyle("");
            return;
        }

        String proto = row.getItem().protocolProperty().get().toUpperCase();

        String color = switch (proto) {
            case "TCP" -> "rgba(50, 205, 50, 0.25)";
            case "UDP" -> "rgba(30, 144, 255, 0.25)";
            case "ARP" -> "rgba(255, 165, 0, 0.25)";
            case "ICMPV4", "ICMPV6" -> "rgba(255, 105, 180, 0.25)";
            case "IGMP" -> "rgba(200, 100, 200, 0.25)";
            default -> "rgba(128, 128, 128, 0.25)";
        };

        row.setStyle("-fx-text-fill: black; -fx-background-color: " + color + ";");
    }

    private void setupSearchFilter() {
        filterField.textProperty().addListener((observable, oldVal, newVal) -> filteredList.setPredicate(packet -> {
            if (newVal == null || newVal.isEmpty()) {
                return true;
            }

            String lower = newVal.toLowerCase();

            return safeContains(packet.getSource(), lower) ||
                    safeContains(packet.getDestination(), lower) ||
                    safeContains(packet.getProtocol(), lower) ||
                    safeContains(packet.getInfo(), lower);
        }));
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

    private boolean safeContains(String text, String filter) {
        return text != null && text.toLowerCase().contains(filter);
    }
}