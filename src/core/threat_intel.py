import requests
import yaml
import logging
from datetime import datetime, timedelta

class ThreatIntelligence:
    def __init__(self, config_path='config/ioc_config.yaml'):
        self.config = self.load_config(config_path)
        self.cache = {}
        self.logger = logging.getLogger(__name__)
        
    def load_config(self, path):
        with open(path, 'r') as f:
            return yaml.safe_load(f)
        
    def check_ioc(self, indicator, ioc_type='ip'):
        """Check indicator against multiple threat feeds"""
        results = {}
        
        # Check cache first
        if indicator in self.cache:
            if self.cache[indicator]['expiration'] > datetime.now():
                return self.cache[indicator]['results']
        
        # Check configured feeds
        for feed_name, feed_config in self.config['feeds'].items():
            try:
                if feed_config['enabled']:
                    url = feed_config['url'].format(indicator=indicator, type=ioc_type)
                    headers = {'API-Key': feed_config.get('api_key', '')} if 'api_key' in feed_config else {}
                    
                    response = requests.get(url, headers=headers, timeout=5)
                    if response.status_code == 200:
                        results[feed_name] = self.parse_response(feed_config['parser'], response.json())
            except Exception as e:
                self.logger.error(f"Error querying {feed_name}: {str(e)}")
        
        # Cache results
        self.cache[indicator] = {
            'results': results,
            'expiration': datetime.now() + timedelta(hours=1)
        }
        
        return results
    
    def parse_response(self, parser_type, data):
        """Parse different threat feed response formats"""
        if parser_type == 'otx':
            pulses = data.get('pulses', [])
            return {
                'malicious': len(pulses) > 0,
                'pulse_count': len(pulses),
                'references': [p['name'] for p in pulses]
            }
        elif parser_type == 'abusech':
            return {
                'malicious': data.get('query_status') == 'ok',
                'threat': data.get('threat'),
                'urlhaus_reference': data.get('urlhaus_reference')
            }
        # Add more parsers as needed
        return data