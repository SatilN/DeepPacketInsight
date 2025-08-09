# src/suricata_generator.py
def create_suricata_rule(alert):
    """Convert analysis findings into Suricata IDS rules"""
    rule_template = (
        f"alert {alert['protocol']} {alert['src_ip']} any -> {alert['dst_ip']} any "
        f"(msg:\"{alert['name']} detected\"; flow:{alert['direction']}; "
        f"content:\"{alert['signature']}\"; threshold:type limit, track by_src, count 1, seconds 60; "
        f"sid:{alert['sid']}; rev:1;)"
    )
    return rule_template

# Example usage:
c2_alert = {
    'name': 'C2 Beaconing',
    'protocol': 'tcp',
    'src_ip': 'any',
    'dst_ip': '$EXTERNAL_NET',
    'direction': 'established',
    'signature': '|01 00 00 00 01|',  # Example C2 pattern
    'sid': 2010001
}
print(create_suricata_rule(c2_alert))