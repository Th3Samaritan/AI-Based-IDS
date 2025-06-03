# prediction_logger.py

import csv
import os
from datetime import datetime

class PredictionLogger:
    def __init__(self, csv_file):
        self.csv_file = csv_file
        if not os.path.exists(csv_file):
            with open(csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp", "source_ip", "destination_ip", "label", "confidence"
                ])

    def log(self, packet_info, label, confidence):
        with open(self.csv_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().isoformat(),
                packet_info.get("source_ip"),
                packet_info.get("destination_ip"),
                label,
                f"{confidence:.4f}"
            ])
