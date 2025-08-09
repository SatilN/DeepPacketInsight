# src/grafana_exporter.py
import json
from datetime import datetime

def generate_grafana_json(analysis_data):
    """Convert analysis results to Grafana-compatible format"""
    return {
        "panels": [
            {
                "title": "Threat Distribution",
                "type": "pie",
                "targets": [{
                    "sql": "SELECT threat_type, count() FROM alerts GROUP BY threat_type",
                    "raw": True
                }]
            },
            {
                "title": "Network Traffic Timeline",
                "type": "graph",
                "targets": [{
                    "sql": "SELECT time, packet_count FROM traffic_stats",
                    "interval": "1m"
                }]
            }
        ],
        "timestamp": datetime.utcnow().isoformat()
    }