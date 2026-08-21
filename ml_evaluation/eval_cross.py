"""
eval_cross.py — Cross-dataset evaluation using tshark
"""

import os
import subprocess
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report


def extract_features(pcap_path):
    try:
        cmd_in = f"tshark -r {pcap_path} -Y 'ip.src==10.0.0.2' -T fields -e frame.time_relative -e frame.len 2>/dev/null"
        res_in = subprocess.check_output(cmd_in, shell=True).decode().strip().splitlines()
        
        cmd_out = f"tshark -r {pcap_path} -Y 'ip.src==10.0.0.1' -T fields -e frame.time_relative -e frame.len 2>/dev/null"
        res_out = subprocess.check_output(cmd_out, shell=True).decode().strip().splitlines()

        in_sizes  = [int(r.split('\t')[1]) for r in res_in  if r and '\t' in r]
        out_sizes = [int(r.split('\t')[1]) for r in res_out if r and '\t' in r]
        in_bytes  = sum(in_sizes)
        out_bytes = sum(out_sizes)
        in_pkts   = len(in_sizes)
        out_pkts  = len(out_sizes)

        in_times = [float(r.split('\t')[0]) for r in res_in if r and '\t' in r]
        if len(in_times) >= 2:
            iats       = [in_times[i+1] - in_times[i] for i in range(len(in_times)-1)]
            iat_mean   = sum(iats) / len(iats)
            iat_range  = max(iats) - min(iats)
            iat_median = sorted(iats)[len(iats)//2]
        else:
            iat_mean = iat_range = iat_median = 0.0

        return [in_bytes, out_bytes, in_pkts, out_pkts, iat_mean, iat_range, iat_median]
    except Exception:
        return None


COLS = ['in_bytes', 'out_bytes', 'in_pkts', 'out_pkts',
        'iat_mean', 'iat_range', 'iat_median']


def build_dataset(data_dir):
    features_list, labels = [], []
    print(f"[*] Loading {data_dir}...")
    for filename in sorted(os.listdir(data_dir)):
        if not filename.endswith(".pcap"):
            continue
        feat = extract_features(os.path.join(data_dir, filename))
        if feat:
            features_list.append(feat)
            labels.append(filename.split('_')[0])
    return pd.DataFrame(features_list, columns=COLS), labels


if __name__ == "__main__":
    X_clean, y_clean = build_dataset("clean_dataset")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_clean, y_clean)
    print(f"[*] Model 1 trained on {len(y_clean)} clean samples.")

    X_stob, y_stob = build_dataset("stob_dataset")
    y_pred = model.predict(X_stob)

    acc = accuracy_score(y_stob, y_pred)
    print("\n" + "="*45)
    print(f"CROSS-EVAL ACCURACY (clean -> stob): {acc * 100:.2f}%")
    print(f"  (Random chance baseline for 10 classes: 10.00%)")
    print("="*45)
    print("\nDetailed Report:")
    print(classification_report(y_stob, y_pred))