# ids.py

from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import queue
from datetime import datetime
import psutil

from features_mapper import map_features
from model_factory import load_engine
from prediction_logger import PredictionLogger
from alert_system import AlertSystem

# ✅ Cross-platform interface auto-detection (Windows + Linux)
def get_default_interface():
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    exclude = ("loopback", "lo", "vmware", "virtual", "bluetooth", "local area connection", "isatap")

    candidates = []
    for iface, iface_stats in stats.items():
        iface_lower = iface.lower()
        if iface_stats.isup and not any(e in iface_lower for e in exclude):
            for snic in addrs.get(iface, []):
                if snic.family.name == 'AF_INET':  # IPv4
                    candidates.append((iface, snic.address))

    if not candidates:
        raise RuntimeError("❌ No active network interface with IPv4 found.")

    print(f"[✓] Available interfaces with IPv4: {candidates}")
    return candidates[0][0]

class PacketCapture:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()

    def packet_callback(self, packet):
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)

    def start_capture(self, interface):
        def capture_thread():
            sniff(
                iface=interface,
                prn=self.packet_callback,
                store=0,
                stop_filter=lambda _: self.stop_capture.is_set()
            )

        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()

class TrafficAnalyzer:
    def __init__(self):
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst)
            stats = self.flow_stats[flow_key]

            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time

            if not stats['start_time']:
                stats['start_time'] = current_time
            stats['last_time'] = current_time

            return stats
        return None

class IntrusionDetectionSystem:
    def __init__(self, interface=None):
        self.interface = interface or get_default_interface()
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine, self.config = load_engine()
        self.alert_system = AlertSystem()
        self.logger = PredictionLogger(self.config.get("log_file", "predictions_log.csv"))

    def start(self):
        print(f"[{datetime.now().isoformat()}] ✅ IDS started on interface: {self.interface}")
        self.packet_capture.start_capture(self.interface)

        try:
            while True:
                try:
                    packet = self.packet_capture.packet_queue.get(timeout=1)
                    stats = self.traffic_analyzer.analyze_packet(packet)

                    if stats:
                        features = map_features(packet, stats)
                        threats = self.detection_engine.detect_threats(features)

                        packet_info = {
                            'source_ip': packet[IP].src,
                            'destination_ip': packet[IP].dst
                        }

                        for threat in threats:
                            self.alert_system.generate_alert(threat, packet_info)

                            if threat['type'] == 'classifier':
                                self.logger.log(packet_info, threat['label'], threat['confidence'])

                except queue.Empty:
                    continue

        except KeyboardInterrupt:
            print(f"[{datetime.now().isoformat()}] 🔴 IDS stopped.")
            self.packet_capture.stop()
