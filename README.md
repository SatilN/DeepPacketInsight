# DeepPacket Insight: Advanced Network Traffic Analysis

DeepPacket Insight is an advanced PCAP analysis tool designed for cybersecurity professionals. It provides comprehensive network traffic analysis with threat intelligence integration, behavioral anomaly detection, and professional reporting.

## Features

- **PCAP Processing**: Extract metadata from network packets
- **Threat Intelligence**: Integrates with multiple threat feeds
- **Behavioral Analysis**: Detect C2 beaconing, DNS tunneling, and more
- **GeoIP Mapping**: Visualize threat origins on world maps
- **Malware Triage**: Extract and analyze suspicious files
- **Suricata Rules**: Generate IDS rules from findings
- **Grafana Integration**: Export data for visualization
- **Container Support**: Docker-ready for easy deployment

## Getting Started

### Prerequisites
- Python 3.10+
- libpcap-dev
- MaxMind GeoLite2 Database (free license required)

### Installation
```bash
git clone https://github.com/yourusername/DeepPacketInsight.git
cd DeepPacketInsight
pip install -r requirements.txt