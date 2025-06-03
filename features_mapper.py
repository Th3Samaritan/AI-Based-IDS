# features_mapper.py

def map_features(packet, stats):
    """
    Extracts the model-compatible feature vector from a packet + flow stats.
    The model expects:
        - packet_size
        - flow_duration
        - packet_rate
        - byte_rate
        - window_size
    """
    flow_duration = stats['last_time'] - stats['start_time']
    flow_duration = flow_duration if flow_duration > 0 else 1e-6

    return {
        'packet_size': len(packet),
        'flow_duration': flow_duration,
        'packet_rate': stats['packet_count'] / flow_duration,
        'byte_rate': stats['byte_count'] / flow_duration,
        'window_size': packet[TCP].window if TCP in packet else 0,
        'tcp_flags': packet[TCP].flags if TCP in packet else 0
    }
