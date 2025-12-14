# JCap

A lightweight, real-time network packet sniffer built with **Java**, **JavaFX**, and **Pcap4J**.

## Features
* **Real-time Capture:** Sniff traffic on any network interface.
* **Protocol Analysis:** Color-coded support for TCP, UDP, ICMP, and ARP.
* **Deep Inspection:** View raw Hex and ASCII payload dumps.
* **Filtering:** Standard BPF syntax (e.g., `tcp port 80`).

## Requirements
1.  **Java 17+** & **Maven**.
2.  **Packet Capture Driver** (Critical):
    * **Windows:** [Npcap](https://npcap.com/) (Check *"Install in WinPcap API-compatible Mode"*).
    * **Linux:** `sudo apt install libpcap-dev`
    * **macOS:** `brew install libpcap`
## Installation & Run

### 1. Install
```bash
mvn clean install
````

### 2\. Run

```bash
mvn javafx:run
```

> **⚠️ IMPORTANT:** Capturing packets requires **Admin Privileges**.
>
>   * **Windows:** Run your terminal or IDE as **Administrator**.
>   * **Linux/macOS:** Use `sudo` if no devices are found.