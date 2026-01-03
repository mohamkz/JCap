package com.jcap.service;

import com.jcap.model.PacketModel;
import javafx.concurrent.Task;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class DatabaseService {

    private static final Logger logger = LoggerFactory.getLogger(DatabaseService.class);
    private static final String DB_URL = "jdbc:sqlite:jcap_history.db";

    public static void initialize() {
        try (Connection conn = DriverManager.getConnection(DB_URL)) {
            Statement stmt = conn.createStatement();

            String sqlSessions = "CREATE TABLE IF NOT EXISTS sessions (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "name TEXT UNIQUE, " +
                    "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)";
            stmt.execute(sqlSessions);

            String sqlPackets = "CREATE TABLE IF NOT EXISTS packets (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "session_id INTEGER, " +
                    "num INTEGER, " +
                    "time TEXT, " +
                    "src TEXT, " +
                    "dst TEXT, " +
                    "proto TEXT, " +
                    "len INTEGER, " +
                    "info TEXT, " +
                    "payload BLOB, " +
                    "FOREIGN KEY(session_id) REFERENCES sessions(id))";
            stmt.execute(sqlPackets);

            logger.info("Database initialized successfully.");
        } catch (SQLException e) {
            logger.error("Failed to initialize database.", e);
        }
    }

    public static Task<Boolean> saveCapture(String sessionName, List<PacketModel> packets) {
        return new Task<>() {
            @Override
            protected Boolean call() throws Exception {
                if (packets.isEmpty()) {
                    logger.warn("Save requested for '{}', but packet list is empty. Aborting.", sessionName);
                    return false;
                }

                long start = System.currentTimeMillis();

                String insertSession = "INSERT INTO sessions(name) VALUES(?)";
                String insertPacket = "INSERT INTO packets(session_id, num, time, src, dst, proto, len, info, payload) VALUES(?,?,?,?,?,?,?,?,?)";

                try (Connection conn = DriverManager.getConnection(DB_URL)) {
                    conn.setAutoCommit(false);

                    int sessionId = -1;
                    try (PreparedStatement stmt = conn.prepareStatement(insertSession, Statement.RETURN_GENERATED_KEYS)) {
                        stmt.setString(1, sessionName);
                        stmt.executeUpdate();
                        var rs = stmt.getGeneratedKeys();
                        if (rs.next()) sessionId = rs.getInt(1);
                    }

                    logger.debug("Created session ID: {}", sessionId);

                    try (PreparedStatement stmt = conn.prepareStatement(insertPacket)) {
                        int count = 0;
                        for (PacketModel p : packets) {
                            stmt.setInt(1, sessionId);
                            stmt.setInt(2, p.getNumber());
                            stmt.setString(3, p.getTimestamp());
                            stmt.setString(4, p.getSource());
                            stmt.setString(5, p.getDestination());
                            stmt.setString(6, p.getProtocol());
                            stmt.setInt(7, p.getLength());
                            stmt.setString(8, p.getInfo());
                            stmt.setBytes(9, p.getPayload());

                            stmt.addBatch();

                            if (++count % 1000 == 0) {
                                stmt.executeBatch();
                                logger.debug("Saved batch of 1000 packets...");
                            }
                        }
                        stmt.executeBatch();
                    }

                    conn.commit();

                    long duration = System.currentTimeMillis() - start;
                    logger.info("Save complete! wrote {} packets in {} ms.", packets.size(), duration);
                    return true;

                } catch (SQLException e) {
                    logger.error("Database error during save.", e);
                }
                return null;
            }
        };
    }

    public static List<String> getCaptureNames() {
        List<String> names = new ArrayList<>();
        String sql = "SELECT name FROM sessions ORDER BY id DESC";

        logger.debug("Fetching capture list...");

        try (Connection conn = DriverManager.getConnection(DB_URL);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                names.add(rs.getString("name"));
            }
        } catch (SQLException e) {
            logger.error("Failed to fetch capture names.", e);
        }
        return names;
    }

    public static List<PacketModel> loadCapture(String sessionName) {
        List<PacketModel> list = new ArrayList<>();
        String sql = "SELECT p.* FROM packets p " +
                "JOIN sessions s ON p.session_id = s.id " +
                "WHERE s.name = ? ORDER BY p.num";

        logger.info("Loading capture '{}'...", sessionName);
        long start = System.currentTimeMillis();

        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, sessionName);
            ResultSet rs = pstmt.executeQuery();

            while (rs.next()) {
                PacketModel p = new PacketModel(
                        rs.getInt("num"),
                        rs.getString("time"),
                        rs.getString("src"),
                        rs.getString("dst"),
                        rs.getString("proto"),
                        rs.getInt("len"),
                        rs.getString("info"),
                        rs.getBytes("payload")
                );
                list.add(p);
            }

            long duration = System.currentTimeMillis() - start;
            logger.info("Loaded {} packets for session '{}' in {} ms.", list.size(), sessionName, duration);

        } catch (SQLException e) {
            logger.error("Failed to load capture '{}'.", sessionName, e);
        }
        return list;
    }

    public static void deleteCapture(String sessionName) {
        String getParams = "SELECT id FROM sessions WHERE name = ?";
        String deletePackets = "DELETE FROM packets WHERE session_id = ?";
        String deleteSession = "DELETE FROM sessions WHERE id = ?";

        try (Connection conn = DriverManager.getConnection(DB_URL)) {
            conn.setAutoCommit(false);

            int sessionId = -1;

            try (PreparedStatement stmt = conn.prepareStatement(getParams)) {
                stmt.setString(1, sessionName);
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    sessionId = rs.getInt("id");
                }
            }

            if (sessionId != -1) {
                try (PreparedStatement stmt = conn.prepareStatement(deletePackets)) {
                    stmt.setInt(1, sessionId);
                    stmt.executeUpdate();
                }

                try (PreparedStatement stmt = conn.prepareStatement(deleteSession)) {
                    stmt.setInt(1, sessionId);
                    stmt.executeUpdate();
                }

                conn.commit();
                logger.info("Deleted session '{}' (ID: {}) and all its packets.", sessionName, sessionId);
            } else {
                logger.warn("Attempted to delete non-existent session: {}", sessionName);
            }

        } catch (SQLException e) {
            logger.error("Failed to delete session '{}'", sessionName, e);
        }
    }
}
