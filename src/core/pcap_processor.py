from scapy.all import rdpcap, IP, TCP, UDP, DNS
import pandas as pd
import numpy as np
import logging

class PCAPAnalyzer:
    def __init__(self, pcap_path):
        self.pcap_path = pcap_path
        self.packets = rdpcap(pcap_path)
        self.df = None
        self.logger = logging.getLogger(__name__)
        
    def process_pcap(self):
        """Convert PCAP to structured DataFrame"""
        data = []
        
        for i, pkt in enumerate(self.packets):
            if not pkt.haslayer(IP):
                continue
                
            entry = {
                'timestamp': pkt.time,
                'src_ip': pkt[IP].src,
                'dst_ip': pkt[IP].dst,
                'protocol': pkt[IP].proto,
                'size': len(pkt),
                'src_port': None,
                'dst_port': None,
                'flags': None,
                'dns_query': None,
                'dns_response': None
            }
            
            if pkt.haslayer(TCP):
                entry['src_port'] = pkt[TCP].sport
                entry['dst_port'] = pkt[TCP].dport
                entry['flags'] = pkt.sprintf("%TCP.flags%")
                
            elif pkt.haslayer(UDP):
                entry['src_port'] = pkt[UDP].sport
                entry['dst_port'] = pkt[UDP].dport
                
                if pkt.haslayer(DNS):
                    dns = pkt[DNS]
                    if dns.qr == 0:  # Query
                        entry['dns_query'] = dns.qd.qname.decode('utf-8', 'ignore')
                    else:  # Response
                        entry['dns_response'] = dns.an.rdata if dns.an else None
            
            data.append(entry)
            
        self.df = pd.DataFrame(data)
        self.logger.info(f"Processed {len(self.df)} network flows")
        return self.df
    
    def get_network_stats(self):
        """Calculate key network statistics"""
        stats = {
            'total_packets': len(self.df),
            'unique_ips': len(set(self.df['src_ip'].tolist() + self.df['dst_ip'].tolist())),
            'top_talkers': self.df.groupby('src_ip').size().nlargest(5).to_dict(),
            'common_ports': self.df['dst_port'].value_counts().nlargest(5).to_dict(),
            'protocol_dist': self.df['protocol'].value_counts().to_dict()
        }
        return stats