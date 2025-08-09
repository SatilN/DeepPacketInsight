# src/geoip_mapper.py
import geoip2.database
import matplotlib.pyplot as plt

def plot_attack_sources(ip_list):
    """Generate world map visualization of threat origins"""
    reader = geoip2.database.Reader('GeoLite2-City.mmdb')
    locations = []
    
    for ip in ip_list:
        try:
            response = reader.city(ip)
            locations.append((response.location.latitude, response.location.longitude))
        except:
            continue
    
    # Plotting
    plt.figure(figsize=(12, 8))
    plt.scatter(*zip(*locations), color='red', alpha=0.5)
    plt.title('Attack Source Locations')
    plt.savefig('attack_map.png')