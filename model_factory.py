# model_factory.py

import json
from detection_engine_binary import BinaryDetectionEngine
from detection_engine_multiclass import MultiClassDetectionEngine

def load_engine(config_path="config.json"):
    with open(config_path) as f:
        config = json.load(f)

    model_type = config.get("model_type", "binary")
    model_path = config.get("model_dir", "models")

    if model_type == "multi":
        return MultiClassDetectionEngine(model_path), config
    else:
        return BinaryDetectionEngine(model_path), config
