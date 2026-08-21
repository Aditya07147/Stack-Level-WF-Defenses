# Complete Linux OS Execution Guide

This guide walks you through setting up, running, and evaluating the **Stack-Level Website Fingerprinting Defenses (Stob)** project on a Linux machine (Ubuntu / Debian / Fedora / Arch).

---

## 1. Prerequisites & Dependencies

On your Linux machine, ensure you have the required compiler toolchain, eBPF libraries, Mininet, and Python dependencies installed.

### Ubuntu / Debian:
```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev mininet tshark tcpdump ethtool iptables iproute2 python3 python3-pip
pip3 install scapy scikit-learn pandas numpy
```

> **Note on Permissions**: Running Mininet, modifying `tc` qdiscs, and loading eBPF programs require root privileges (`sudo`).

---

## 2. Getting the Updated Code on Linux

In your cloned repository on Linux:

```bash
# Fetch latest branches from remote
git fetch origin

# Switch to the fix branch
git checkout fix/ebpf-and-pipeline-fixes

# Ensure you have the latest commits
git pull origin fix/ebpf-and-pipeline-fixes
```

---

## 3. Step-by-Step Workflow

### Step 1: Compile the eBPF Kernel Program

The eBPF timing jitter primitive must be compiled into BPF ELF bytecode targeting the `bpf` architecture.

```bash
make -C ebpf
```
*Or compile manually with Clang:*
```bash
clang -O2 -g -Wall -target bpf -c ebpf/stob_kern.c -o ebpf/stob_kern.o
```

**Verify the compiled bytecode:**
```bash
llvm-objdump -h ebpf/stob_kern.o
```
*(You should see sections named `classifier`, `.maps`, and `license`.)*

---

### Step 2: Running the Network Simulation

Run the experiment runner using `sudo`:

```bash
sudo python3 mininet/run_experiment.py
```

#### What happens during execution:
1. **Mock Sites Check**: If you have your real `mininet/sites/` directory present on Linux, it will be served as-is. If missing, it auto-generates test site assets.
2. **Topology Setup**: Launches Mininet with a 10 Mbps, 5ms delay virtual switch topology (`client` at `10.0.0.1`, `server` at `10.0.0.2`).
3. **Phase 1 (Clean Baseline)**: Fetches pages without defenses, capturing raw traces into `clean_dataset/`.
4. **Phase 2 (STOB Defense)**:
   - Configures `iptables` TCP MSS clamping to 500 bytes in the `mangle` table.
   - Configures the Fair Queueing (`fq`) root qdisc on `server-eth0`.
   - Attaches the compiled eBPF filter `ebpf/stob_kern.o` with the direct-action (`da`) hook.
5. **Phase 3 (Defended Traffic)**: Fetches pages with 3MB volume padding and eBPF monotonic timing jitter, capturing traces into `stob_dataset/`.

**Expected output when eBPF is active:**
```text
*** [STOB] Timing: eBPF jitter active (monotonic EDT + FQ)
*** [STOB] Defense active.
```

---

### Step 3: Running the Machine Learning Evaluations

Once PCAP traces are gathered (or using your existing PCAP datasets):

#### 1. Baseline Model (Clean Traffic)
Trains a Random Forest classifier on undefended traffic to establish the attacker's baseline accuracy (expected ~90%):
```bash
python3 ml_evaluation/train_model1.py
```

#### 2. Cross-Dataset Evaluation (The True Defense Test)
Trains on clean traffic and tests against Stob-defended traffic. If the defense works, accuracy drops close to random guess (~10% for 10 classes):
```bash
python3 ml_evaluation/eval_cross.py
```

#### 3. Adaptive Attacker Model
Trains and tests directly on defended traffic to simulate an attacker that knows the defense is active:
```bash
python3 ml_evaluation/train_model2.py
```

---

## 4. Working Directly with Existing Wireshark / PCAP Traces

If you already have your captured `.pcap` files on Linux:
1. Place undefended `.pcap` files into `./clean_dataset/` (named e.g. `site1_s0.pcap`, `site2_s1.pcap`, etc.).
2. Place defended `.pcap` files into `./stob_dataset/` (named e.g. `site1_s0.pcap`, `site2_s1.pcap`, etc.).
3. Run the ML evaluation scripts directly without running Mininet:
   ```bash
   python3 ml_evaluation/train_model1.py
   python3 ml_evaluation/eval_cross.py
   python3 ml_evaluation/train_model2.py
   ```

---

## 5. Troubleshooting & Useful Diagnostic Commands

### How to verify the eBPF filter is loaded live in Mininet:
In another terminal while Mininet is active:
```bash
sudo tc filter show dev server-eth0 egress
```
You should see output similar to:
```text
filter protocol all pref 49152 bpf chain 0
filter protocol all pref 49152 bpf chain 0 handle 0x1 stob_kern.o:[classifier] direct-action not_in_hw id ...
```

### Clean up stuck Mininet topologies:
If a previous run was interrupted or crashed:
```bash
sudo mn -c
sudo pkill -f mock_server.py
sudo pkill -f tcpdump
```

### Check BPF Filesystem:
If you see BPF filesystem errors:
```bash
sudo mount -t bpf bpf /sys/fs/bpf/
```
