# run_ids.py

import argparse
import json
from ids import IntrusionDetectionSystem

def save_temp_config(model_type: str, config_file: str = "config.json"):
    config = {
        "model_type": model_type,
        "model_dir": "models",
        "log_file": "predictions_log.csv"
    }
    with open(config_file, "w") as f:
        json.dump(config, f, indent=2)

def main():
    parser = argparse.ArgumentParser(description="Run Hybrid ML IDS")
    parser.add_argument("--model", choices=["binary", "multi"], default="binary", help="Classifier mode")
    parser.add_argument("--interface", default="eth0", help="Network interface to sniff")
    args = parser.parse_args()

    save_temp_config(args.model)

    ids = IntrusionDetectionSystem(interface=args.interface)
    ids.start()

if __name__ == "__main__":
    main()
