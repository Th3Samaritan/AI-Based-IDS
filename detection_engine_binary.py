# detection_engine_binary.py

import os
import joblib
import pandas as pd

class BinaryDetectionEngine:
    def __init__(self, model_path="models"):
        self.classifier = joblib.load(os.path.join(model_path, "rf_model.pkl"))
        self.scaler = joblib.load(os.path.join(model_path, "scaler.pkl"))
        self.signature_rules = self.load_signature_rules()

    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda features: (
                    features.get('tcp_flags') == 2 and
                    features.get('packet_rate', 0) > 100
                )
            },
            'port_scan': {
                'condition': lambda features: (
                    features.get('packet_size', 0) < 100 and
                    features.get('packet_rate', 0) > 50
                )
            }
        }

    def detect_threats(self, features: dict) -> list:
        threats = []

        # Signature-based rules
        for rule_name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'confidence': 1.0
                })

        # Classifier input
        vector_df = pd.DataFrame([[
            features.get(k, 0.0) for k in [
                'packet_size', 'flow_duration', 'packet_rate', 'byte_rate', 'window_size'
            ]
        ]], columns=['packet_size', 'flow_duration', 'packet_rate', 'byte_rate', 'window_size'])

        vector_scaled = self.scaler.transform(vector_df)
        pred = self.classifier.predict(vector_scaled)[0]
        prob = self.classifier.predict_proba(vector_scaled)[0][pred]

        if pred == 1:
            threats.append({
                'type': 'classifier',
                'label': 'ATTACK',
                'confidence': round(prob, 4)
            })

        return threats
