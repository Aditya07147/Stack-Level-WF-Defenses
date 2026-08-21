import os
import subprocess
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
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


def build_dataset(data_dir_name="stob_dataset"):
    if os.path.exists(data_dir_name):
        data_dir = data_dir_name
    elif os.path.exists(os.path.join(REPO_ROOT, data_dir_name)):
        data_dir = os.path.join(REPO_ROOT, data_dir_name)
    else:
        raise FileNotFoundError(f"Dataset directory '{data_dir_name}' not found.")

    features_list = []
    labels = []

    files = [f for f in os.listdir(data_dir) if f.endswith(".pcap")]
    print(f"[*] Extracting features from {len(files)} files in {data_dir}...")

    for i, filename in enumerate(sorted(files)):
        path = os.path.join(data_dir, filename)
        label = filename.split('_')[0]

        feat = extract_features(path)
        if feat:
            features_list.append(feat)
            labels.append(label)

        if (i + 1) % 20 == 0:
            print(f"    Processed {i+1}/{len(files)} files...")

    cols = ['in_bytes', 'out_bytes', 'in_pkts', 'out_pkts',
            'iat_mean', 'iat_range', 'iat_median']
    return pd.DataFrame(features_list, columns=cols), labels


def train_and_evaluate():
    X, y = build_dataset("stob_dataset")
    if len(X) == 0:
        print("[ERROR] No valid PCAP samples found in stob_dataset.")
        return

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42)

    print(f"[*] Training Model 2 on {len(X_train)} defended samples...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("\n" + "="*35)
    print(f"MODEL 2 ACCURACY (STOB TRAIN+TEST): {accuracy_score(y_test, y_pred) * 100:.2f}%")
    print("="*35)
    print("\nDetailed Report:")
    print(classification_report(y_test, y_pred))

if __name__ == "__main__":
    train_and_evaluate()