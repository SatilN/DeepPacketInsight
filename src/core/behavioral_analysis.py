import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

class BehavioralAnalyzer:
    def __init__(self):
        self.models = {}
        
    def detect_c2_beaconing(self, flow_df):
        """Identify command and control beaconing patterns"""
        if flow_df.empty:
            return []
            
        # Calculate time intervals
        flow_df = flow_df.sort_values('timestamp')
        flow_df['interval'] = flow_df['timestamp'].diff()
        
        # Filter relevant flows
        filtered = flow_df[flow_df['interval'] > 0].copy()
        
        if len(filtered) < 10:
            return []
            
        # Calculate stability metrics
        cv = np.std(filtered['interval']) / np.mean(filtered['interval'])
        entropy = self.calculate_entropy(filtered['size'])
        
        # Detect beaconing (low variation in timing)
        beaconing_suspicion = cv < 0.3 and entropy > 0.8
        
        return [{
            'type': 'c2_beaconing',
            'src_ip': filtered.iloc[0]['src_ip'],
            'dst_ip': filtered.iloc[0]['dst_ip'],
            'confidence': (1 - cv) * 0.7 + entropy * 0.3,
            'metrics': {
                'interval_cv': cv,
                'entropy': entropy,
                'packet_count': len(filtered)
            }
        }] if beaconing_suspicion else []
    
    def detect_dns_tunneling(self, dns_flows):
        """Identify potential DNS tunneling attempts"""
        alerts = []
        for domain, group in dns_flows.groupby('dns_query'):
            domain = domain.strip('.')  # Clean domain
            if not domain:
                continue
                
            # Calculate domain characteristics
            subdomain = domain.split('.')[0]
            length = len(subdomain)
            entropy = self.calculate_entropy(subdomain.encode())
            
            # Detection logic
            if length > 50 or entropy > 0.9:
                alerts.append({
                    'type': 'dns_tunneling',
                    'domain': domain,
                    'src_ip': group.iloc[0]['src_ip'],
                    'confidence': min(0.9, 0.4 + (length/100) + (entropy * 0.5)),
                    'metrics': {
                        'subdomain_length': length,
                        'entropy': entropy,
                        'query_count': len(group)
                    }
                })
                
        return alerts
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
            
        if isinstance(data, pd.Series):
            data = data.values
            
        if isinstance(data, np.ndarray):
            _, counts = np.unique(data, return_counts=True)
            probs = counts / counts.sum()
            return -np.sum(probs * np.log2(probs))
        
        # For string data
        from collections import Counter
        counter = Counter(data)
        probs = [c / len(data) for c in counter.values()]
        return -sum(p * np.log2(p) for p in probs)