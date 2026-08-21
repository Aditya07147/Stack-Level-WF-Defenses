from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.link import TCLink
import time
import os
import sys

# --- PATH CONFIGURATION ---
MININET_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT   = os.path.abspath(os.path.join(MININET_DIR, ".."))
EBPF_OBJ    = os.path.join(REPO_ROOT, "ebpf", "stob_kern.o")
MOCK_SERVER = os.path.join(MININET_DIR, "mock_server.py")
SITES_DIR   = os.path.join(MININET_DIR, "sites")
CLEAN_DIR   = os.path.join(REPO_ROOT, "clean_dataset")
STOB_DIR    = os.path.join(REPO_ROOT, "stob_dataset")

# --- CONFIGURATION ---
SITES = [f"site{i}" for i in range(1, 11)]
CLEAN_SAMPLES = 10
STOB_SAMPLES  = 5
SERVER_IP     = "10.0.0.2"
SESSION_TARGET_BYTES = 3 * 1024 * 1024  # 3MB — used for STOB padding

SITE_FILES = {
    "site1":  [("index.html", "get")],
    "site2":  [("index.html", "get")],
    "site3":  [("index.html", "get")],
    "site4":  [(f"img{i}.jpg", "get") for i in range(1, 6)],
    "site5":  [(f"data{i}.bin", "get") for i in range(1, 11)],
    "site6":  [("index.html", "get")],
    "site7":  [("index.html", "get")],
    "site8":  [("index.html", "get")],
    "site9":  [("index.html", "get")],
    "site10": [("index.html", "get")],
}

# ─────────────────────────────────────────────
# TOPOLOGY
# ─────────────────────────────────────────────

class WF_Topo(Topo):
    def build(self):
        s1     = self.addSwitch('s1', cls=OVSSwitch, failMode='standalone')
        client = self.addHost('client', ip='10.0.0.1/24')
        server = self.addHost('server', ip='10.0.0.2/24')
        self.addLink(client, s1, bw=10, delay='5ms')
        self.addLink(server, s1, bw=10, delay='5ms')

# ─────────────────────────────────────────────
# STOB DEFENSE
# ─────────────────────────────────────────────

def apply_stob_defense(net):
    server = net.get('server')
    print("\n*** [STOB] Applying defense...")

    # Mount BPF fs (required for eBPF TC programs)
    os.system("mount -t bpf bpf /sys/fs/bpf/ 2>/dev/null || true")

    # --- MSS Clamping via iptables (in mangle table) ---
    server.cmd("iptables -t mangle -F 2>/dev/null || true")
    server.cmd("iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 500")

    # --- Timing Regularization via eBPF & FQ ---
    server.cmd("tc qdisc del dev server-eth0 clsact 2>/dev/null || true")
    server.cmd("tc qdisc del dev server-eth0 root 2>/dev/null || true")
    server.cmd("tc qdisc add dev server-eth0 root fq")
    server.cmd("tc qdisc add dev server-eth0 clsact")

    # Attach eBPF classifier with direct-action (da) flag
    out = server.cmd(f"tc filter add dev server-eth0 egress bpf obj {EBPF_OBJ} sec classifier da 2>&1")
    if "Unable to load" in out or "failed" in out.lower() or "error" in out.lower():
        print(f"[WARN] eBPF loading failed: {out.strip()}")
        print("[WARN] Falling back to netem jitter...")
        server.cmd("tc qdisc del dev server-eth0 clsact 2>/dev/null || true")
        server.cmd("tc qdisc del dev server-eth0 root 2>/dev/null || true")
        server.cmd("tc qdisc add dev server-eth0 root netem delay 5ms 5ms distribution normal")
        print("*** [STOB] Timing: netem jitter active (5ms +/- 5ms)")
    else:
        print("*** [STOB] Timing: eBPF jitter active (monotonic EDT + FQ)")

    print("*** [STOB] Defense active.")

# ─────────────────────────────────────────────
# FETCH HELPERS
# ─────────────────────────────────────────────

def fetch_site_mininet(client, site):
    """Fetch all resources for a site. Returns total bytes downloaded."""
    total_bytes = 0
    for (filename, _) in SITE_FILES[site]:
        url = f"http://{SERVER_IP}:8080/{site}/{filename}"
        out = client.cmd(f"curl -s -w '%{{size_download}}' {url} -o /dev/null")
        try:
            total_bytes += int(out.strip())
        except ValueError:
            print(f"    [WARN] Could not parse byte count for {url}: '{out.strip()}'")
    return total_bytes

def apply_session_padding_mininet(client, total_bytes):
    """Top up session to SESSION_TARGET_BYTES. Only called during STOB collection."""
    padding_needed = max(0, SESSION_TARGET_BYTES - total_bytes)
    client.cmd(f"curl -s http://{SERVER_IP}:8080/__pad__?need={padding_needed} -o /dev/null")

# ─────────────────────────────────────────────
# COLLECTION
# ─────────────────────────────────────────────

def run_clean_collection(net, data_dir, samples):
    """Raw, natural traffic — NO padding, NO defense."""
    client = net.get('client')
    os.makedirs(data_dir, exist_ok=True)

    print(f"\n*** [CLEAN] Starting collection -> {data_dir}/")
    print(f"    Sites: {len(SITES)}, Samples per site: {samples}")
    print(f"    Total pcaps: {len(SITES) * samples}\n")

    for site in SITES:
        for s in range(samples):
            pcap_file = os.path.join(data_dir, f"{site}_s{s}.pcap")

            tcpdump_cmd = f"tcpdump -i client-eth0 -s 96 -w {pcap_file} port 8080 2>/dev/null &"
            client.cmd(tcpdump_cmd)
            time.sleep(1.5)

            print(f"  [*] CLEAN | {site} | sample {s+1}/{samples}")
            fetch_site_mininet(client, site)

            time.sleep(1)
            client.cmd("pkill -f tcpdump")
            time.sleep(0.5)

    # Verify pcap size after first site to catch anomalies early
    first_pcap = os.path.join(data_dir, "site1_s0.pcap")
    if os.path.exists(first_pcap):
        size_mb = os.path.getsize(first_pcap) / (1024 * 1024)
        print(f"\n[SIZE CHECK] site1_s0.pcap = {size_mb:.2f} MB")
        if size_mb > 2:
            print("[WARN] Pcap is larger than expected for -s 96 snaplen.")
        else:
            print("[OK] Pcap size looks good.")

    print(f"\n*** [CLEAN] Done. Traces saved in {data_dir}/")


def run_stob_collection(net, data_dir, samples):
    """Defended traffic — session-level volume padding + timing jitter."""
    client = net.get('client')
    os.makedirs(data_dir, exist_ok=True)

    print(f"\n*** [STOB] Starting collection -> {data_dir}/")
    print(f"    Sites: {len(SITES)}, Samples per site: {samples}")
    print(f"    Total pcaps: {len(SITES) * samples}\n")

    for site in SITES:
        for s in range(samples):
            pcap_file = os.path.join(data_dir, f"{site}_s{s}.pcap")

            tcpdump_cmd = f"tcpdump -i client-eth0 -s 96 -w {pcap_file} port 8080 2>/dev/null &"
            client.cmd(tcpdump_cmd)
            time.sleep(1.5)

            print(f"  [*] STOB | {site} | sample {s+1}/{samples}")
            total_bytes = fetch_site_mininet(client, site)
            apply_session_padding_mininet(client, total_bytes)

            time.sleep(1)
            client.cmd("pkill -f tcpdump")
            time.sleep(0.5)

    print(f"\n*** [STOB] Done. Traces saved in {data_dir}/")

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == '__main__':
    # Ensure site assets exist
    if not os.path.exists(SITES_DIR) or not os.listdir(SITES_DIR):
        print("[*] Sites directory missing or empty. Auto-generating mock sites...")
        sys.path.insert(0, MININET_DIR)
        from generate_sites import generate_sites
        generate_sites(SITES_DIR)

    # Check eBPF compilation
    if not os.path.exists(EBPF_OBJ):
        print(f"[ERROR] eBPF object not found at: {EBPF_OBJ}")
        print("        Please compile it with: clang -O2 -g -target bpf -c ebpf/stob_kern.c -o ebpf/stob_kern.o")
        sys.exit(1)

    os.system("mn -c 2>/dev/null")

    print("*** Building virtual network...")
    topo = WF_Topo()
    net  = Mininet(topo=topo, link=TCLink, controller=None)
    net.start()

    server = net.get('server')
    client = net.get('client')

    # Disable TSO/GSO/GRO so packets are observed at wire segmentation
    server.cmd("ethtool -K server-eth0 gro off gso off tso off 2>/dev/null")
    client.cmd("ethtool -K client-eth0 gro off gso off tso off 2>/dev/null")

    # Start mock server
    server.cmd(f"python3 {MOCK_SERVER} &")
    time.sleep(2)

    test = os.popen("tcpdump --help 2>&1 | grep snaplen").read()
    if not test:
        print("[WARN] Could not verify tcpdump -s support. Proceeding anyway.")
    else:
        print("[OK] tcpdump snaplen support confirmed.")

    try:
        # Phase 1: clean, undefended traffic
        run_clean_collection(net, CLEAN_DIR, CLEAN_SAMPLES)

        # Phase 2: apply STOB defense
        apply_stob_defense(net)

        # Phase 3: defended traffic with padding + jitter
        run_stob_collection(net, STOB_DIR, STOB_SAMPLES)

    finally:
        os.system("pkill -f mock_server.py")
        server.cmd("tc qdisc del dev server-eth0 clsact 2>/dev/null || true")
        server.cmd("tc qdisc del dev server-eth0 root 2>/dev/null || true")
        server.cmd("iptables -t mangle -F 2>/dev/null || true")
        net.stop()
        print("\n*** [CLEANUP] Done.")