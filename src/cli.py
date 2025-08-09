import argparse
import logging
import json
import yaml
import os
from datetime import datetime
from src.core import pcap_processor, threat_intel, behavioral_analysis, reporting
from src.enhancements import suricata_generator, geoip_mapper, malware_triage

def main():
    parser = argparse.ArgumentParser(description="DeepPacket Insight - Advanced PCAP Analysis")
    parser.add_argument("pcap", nargs="?", help="Path to PCAP file")
    parser.add_argument("--pcap-dir", help="Directory containing PCAP files")
    parser.add_argument("--output", default="reports", help="Output directory")
    parser.add_argument("--geoip", action="store_true", help="Enable GeoIP mapping")
    parser.add_argument("--suricata", action="store_true", help="Generate Suricata rules")
    parser.add_argument("--grafana", action="store_true", help="Export to Grafana")
    parser.add_argument("--malware", action="store_true", help="Enable malware triage")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, 
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Process PCAPs
    pcap_files = []
    if args.pcap:
        pcap_files.append(args.pcap)
    elif args.pcap_dir:
        pcap_files = [os.path.join(args.pcap_dir, f) 
                     for f in os.listdir(args.pcap_dir) 
                     if f.endswith('.pcap') or f.endswith('.pcapng')]
    
    for pcap_file in pcap_files:
        analyze_pcap(pcap_file, args)
    
def analyze_pcap(pcap_path, args):
    logger = logging.getLogger(__name__)
    logger.info(f"Starting analysis of {pcap_path}")
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    base_name = os.path.splitext(os.path.basename(pcap_path))[0]
    report_dir = os.path.join(args.output, base_name)
    os.makedirs(report_dir, exist_ok=True)
    
    # PCAP Processing
    processor = pcap_processor.PCAPAnalyzer(pcap_path)
    df = processor.process_pcap()
    stats = processor.get_network_stats()
    
    # Threat Intelligence
    ti = threat_intel.ThreatIntelligence()
    ti_results = {}
    for ip in set(df['src_ip'].tolist() + df['dst_ip'].tolist()):
        ti_results[ip] = ti.check_ioc(ip, 'ip')
    
    # Behavioral Analysis
    analyzer = behavioral_analysis.BehavioralAnalyzer()
    alerts = []
    
    # Analyze each flow
    for (src, dst), flow in df.groupby(['src_ip', 'dst_ip']):
        flow_alerts = analyzer.detect_c2_beaconing(flow)
        alerts.extend(flow_alerts)
        
    # DNS-specific analysis
    dns_flows = df[df['dns_query'].notnull()]
    dns_alerts = analyzer.detect_dns_tunneling(dns_flows)
    alerts.extend(dns_alerts)
    
    # GeoIP Mapping
    geo_data = {}
    if args.geoip:
        mapper = geoip_mapper.GeoIPMapper()
        geo_data = mapper.map_ips(list(set(df['src_ip'].tolist() + df['dst_ip'].tolist())))
    
    # Malware Triage
    malware_results = {}
    if args.malware:
        triage = malware_triage.MalwareTriage()
        extracted_files = triage.extract_files(pcap_path)
        malware_results = {f['sha256']: triage.analyze_file(f['data']) for f in extracted_files}
    
    # Generate Report
    reporter = reporting.HTMLReporter()
    report_html = reporter.generate_report({
        'pcap_name': os.path.basename(pcap_path),
        'stats': stats,
        'alerts': alerts,
        'ti_results': ti_results,
        'geo_data': geo_data,
        'malware_results': malware_results
    })
    
    with open(os.path.join(report_dir, f'report_{base_name}.html'), 'w') as f:
        f.write(report_html)
    
    # Generate Suricata Rules
    if args.suricata:
        generator = suricata_generator.SuricataGenerator()
        rules = [generator.create_rule(alert) for alert in alerts if alert['confidence'] > 0.7]
        with open(os.path.join(report_dir, f'rules_{base_name}.rules'), 'w') as f:
            f.write('\n'.join(rules))
    
    # Grafana Export
    if args.grafana:
        grafana_exporter.export_to_grafana({
            'pcap': base_name,
            'stats': stats,
            'alerts': alerts
        })
    
    logger.info(f"Analysis complete for {pcap_path}. Report saved to {report_dir}")

if __name__ == "__main__":
    main()