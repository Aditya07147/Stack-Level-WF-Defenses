"""
eval_cross.py  —  Cross-dataset evaluation

This is the evaluation that measures whether STOB works.

Procedure:
  1. Train the model on CLEAN traffic (no defense).
  2. Test it on STOB-defended traffic.

If the defense works, accuracy should drop toward ~10%
(random chance for 10 classes). If it stays high, either:
  - The volume features still leak identity (padding/normalization bug), or
  - The timing jitter isn't strong enough to destroy IAT features.
"""

import os
import subprocess
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))


def extract_features(pcap_path):
    try:
        # Incoming packets (from server 10.0.0.2)
        cmd_in = f"tshark -r \"{pcap_path}\" -Y 'ip.src==10.0.0.2' -T fields -e frame.time_relative -e frame.len 2>/dev/null"
        res_in = subprocess.check_output(cmd_in, shell=True).decode().strip().splitlines()

        # Outgoing packets (from client 10.0.0.1)
        cmd_out = f"tshark -r \"{pcap_path}\" -Y 'ip.src==10.0.0.1' -T fields -e frame.time_relative -e frame.len 2>/dev/null"
        res_out = subprocess.check_output(cmd_out, shell=True).decode().strip().splitlines()

        # Volume features (original wire lengths)
        in_sizes  = [int(r.split('\t')[1]) for r in res_in  if r and '\t' in r]
        out_sizes = [int(r.split('\t')[1]) for r in res_out if r and '\t' in r]
        in_bytes  = sum(in_sizes)
        out_bytes = sum(out_sizes)
        in_pkts   = len(in_sizes)
        out_pkts  = len(out_sizes)

        # Timing features (IAT on incoming packets)
        in_times = [float(r.split('\t')[0]) for r in res_in if r and '\t' in r]
        if len(in_times) >= 2:
            iats       = [in_times[i+1] - in_times[i] for i in range(len(in_times)-1)]
            iat_mean   = sum(iats) / len(iats)
            iat_range  = max(iats) - min(iats)
            iat_median = sorted(iats)[len(iats)//2]
        else:
            iat_mean = iat_range = iat_median = 0.0

        return [in_bytes, out_bytes, in_pkts, out_pkts, iat_mean, iat_range, iat_median]

    except Exception as e:
        # Fallback to Scapy using wirelen
        try:
            from scapy.all import rdpcap
            packets = rdpcap(pcap_path)
            in_sizes, out_sizes, in_times = [], [], []
            for pkt in packets:
                if pkt.haslayer('IP'):
                    pkt_len = getattr(pkt, 'wirelen', len(pkt))
                    if pkt['IP'].src == "10.0.0.2":
                        in_sizes.append(pkt_len)
                        in_times.append(float(pkt.time))
                    elif pkt['IP'].src == "10.0.0.1":
                        out_sizes.append(pkt_len)
            in_bytes  = sum(in_sizes)
            out_bytes = sum(out_sizes)
            in_pkts   = len(in_sizes)
            out_pkts  = len(out_sizes)
            if len(in_times) >= 2:
                iats       = [in_times[i+1] - in_times[i] for i in range(len(in_times)-1)]
                iat_mean   = sum(iats) / len(iats)
                iat_range  = max(iats) - min(iats)
                iat_median = sorted(iats)[len(iats)//2]
            else:
                iat_mean = iat_range = iat_median = 0.0
            return [in_bytes, out_bytes, in_pkts, out_pkts, iat_mean, iat_range, iat_median]
        except Exception as inner_e:
            print(f"    [WARN] Failed on {pcap_path}: {e} / {inner_e}")
            return None


COLS = ['in_bytes', 'out_bytes', 'in_pkts', 'out_pkts',
        'iat_mean', 'iat_range', 'iat_median']


def build_dataset(data_dir_name):
    if os.path.exists(data_dir_name):
        data_dir = data_dir_name
    elif os.path.exists(os.path.join(REPO_ROOT, data_dir_name)):
        data_dir = os.path.join(REPO_ROOT, data_dir_name)
    else:
        raise FileNotFoundError(f"Dataset directory '{data_dir_name}' not found.")

    features_list, labels = [], []
    print(f"[*] Loading {data_dir}...")
    files = [f for f in os.listdir(data_dir) if f.endswith(".pcap")]
    for filename in sorted(files):
        feat = extract_features(os.path.join(data_dir, filename))
        if feat:
            features_list.append(feat)
            labels.append(filename.split('_')[0])
    return pd.DataFrame(features_list, columns=COLS), labels


if __name__ == "__main__":
    # Step 1: Train on clean data
    X_clean, y_clean = build_dataset("clean_dataset")
    if len(X_clean) == 0:
        print("[ERROR] No valid PCAP samples in clean_dataset.")
        exit(1)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_clean, y_clean)
    print(f"[*] Model trained on {len(y_clean)} clean samples.")

    # Step 2: Test on STOB-defended data
    X_stob, y_stob = build_dataset("stob_dataset")
    if len(X_stob) == 0:
        print("[ERROR] No valid PCAP samples in stob_dataset.")
        exit(1)

    y_pred = model.predict(X_stob)

    acc = accuracy_score(y_stob, y_pred)
    print("\n" + "="*45)
    print(f"CROSS-EVAL ACCURACY (clean→stob): {acc * 100:.2f}%")
    print(f"  (Random baseline for 10 classes: 10.00%)")
    print("="*45)
    print("\nDetailed Report:")
    print(classification_report(y_stob, y_pred))

    # Interpretation hint
    if acc > 0.5:
        print("\n[!] Accuracy is still HIGH — defense is not working.")
        print("    Check: Are all sites fetching the same number of files?")
        print("    Check: Is stob_kern.o actually loaded? Run: tc filter show dev server-eth0 egress")
    elif acc > 0.2:
        print("\n[~] Accuracy is partially reduced — defense is partially working.")
    else:
        print("\n[✓] Accuracy is near random — STOB defense is effective.")