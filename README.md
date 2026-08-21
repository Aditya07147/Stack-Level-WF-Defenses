

# Stack-Level Website Fingerprinting Defenses (Stob)

An end-to-end empirical replication of **Stob (Stack-level Traffic Obfuscation)**—originally proposed in ACM HotNets '25—to close the *Application-Stack Gap* in Website Fingerprinting (WF) defenses. This project validates how moving obfuscation primitives directly into the Linux kernel prevents standard TCP optimizations from stripping away privacy-focused delays and padding.

---

## Repository Structure

The project is structured logically into standalone pipelines and datasets:

```text
├── clean_dataset/                            # PCAP traces of baseline undefended traffic
├── docs/                                     # Academic deliverables and reference literature
│   ├── CS544_Course_Project_Presentation.pdf # Class presentation slides (PDF)
│   ├── CS544_Course_Project_Report.pdf       # Complete academic project report (PDF)
│   └── Research_Paper.pdf                    # Reference HotNets '25 "Stob" research paper (PDF)
├── ebpf/
│   ├── Makefile                              # Makefile for building eBPF bytecode
│   └── stob_kern.c                           # eBPF C program to inject TC egress timing jitter
├── mininet/
│   ├── generate_sites.py                     # Deterministic generator for 10 mock sites
│   ├── mock_server.py                        # Python server serving 10 sites with dynamic 3MB padding
│   └── run_experiment.py                     # Virtual network topology, data collection, and traffic capture
├── ml_evaluation/
│   ├── train_model1.py                       # Trains baseline classifier on undefended traffic
│   ├── train_model2.py                       # Trains adaptive classifier on defended traffic
│   └── eval_cross.py                         # Evaluates Model 1 on defended traffic
└── stob_dataset/                             # PCAP traces of Stob-defended traffic (jitter + padding)
```

## Background & Motivation

### 1. Website Fingerprinting & The Encryption Paradox
While modern cryptographic protocols like **TLS 1.3** and **QUIC** successfully secure the plaintext payload of network communications, they leave side-channel metadata exposed. Passive network observers, such as ISPs or national censorship firewalls, can apply Deep Learning classifiers (e.g., *k-FP*, *Var-CNN*) to packet sizes, directions, and inter-arrival times (IAT) to construct unique website "fingerprints".

With the industry-wide rollout of **Encrypted Client Hello (ECH)**, even the **Server Name Indication (SNI)** is encrypted, hiding the destination domain entirely. Consequently, traffic analysis of metadata remains the last viable vector for state censors to identify visited websites.

### 2. The "Application-Stack Gap" (Why App-Level Defenses Fail)
Historically, WF countermeasures (e.g., *FRONT*, *WTF-PAD*, *BuFLO*) have been implemented at the **application layer** (inside browsers or web servers). The original paper establishes that these defenses are fundamentally "broken" by the host operating system's network stack:
*   **Asynchronous Send Buffering**: Application writes (`send()`) are copied to socket buffers and transmitted based on TCP ACK-clocking and congestion window (`cwnd`) availability, ignoring precise timing requested by the application.
*   **Packet Coalescing**: To minimize CPU and header overhead, the kernel's TCP layer combines multiple small, obfuscated application writes into single, large maximum transmission unit (MTU) packets.
*   **TSO (TCP Segmentation Offload)**: The NIC hardware splits large segments into MSS-sized packets at line rate without interleaving, destroying application-level delay scheduling.
*   **Inefficient Padding Overhead**: Lacking fine-grained control over timing, app-level defenses resort to heavy dummy padding, introducing unsustainable bandwidth overheads (e.g., **80% in FRONT** and up to **309% in QCSD**).

### 3. The Stob Paradigm: Stack-Level Enforcement
To bridge this gap, the authors of **Stob** propose moving traffic obfuscation directly into the **host network stack** (spanning the transport and packet I/O layers). Operating at the kernel level gives the defense the "final say" over packet sequences. 

Using lightweight kernel technologies like **eBPF (Extended Berkeley Packet Filter)**, applications can push privacy policies (e.g., pacing histograms) to a shared kernel map. This allows the stack to perform microsecond-level timing modifications and dynamic packet sizing on the wire, natively cooperating with Congestion Control Algorithms (CCA) and queuing disciplines (`qdisc`).

### 4. The Censorship Scenario (Early-Connection Defenses)
Real-world state censors must make blocking decisions **early in the connection** (typically within the first 15 to 45 packets) before a client can download the webpage. By evaluating defenses on early-packet sequences, the Stob framework demonstrates that kernel-level packet splitting and pacing delays effectively scramble the traffic fingerprint during the critical "last mile" of handshake and early data transmission.

---

## System Architecture & Implementation

Our implementation targets the two core traffic leaks analyzed by website fingerprinting attacks: **packet timing** (Inter-Arrival Time) and **session volume** (byte counts).

### 1. Timing Obfuscation via eBPF (`ebpf/stob_kern.c`)
To bypass stack-level optimizations like Packet Coalescing and TCP Segmentation Offload (TSO), we implemented timing obfuscation directly in the kernel space. 

Our C program attaches to the **Traffic Control (TC) egress hook** of the interface. When a packet reaches this hook, we modify its departure timestamp (`skb->tstamp`). The Fair Queuing (`FQ`) qdisc then holds the packet until this exact scheduled time, ensuring precise wire-level obfuscation:

```c
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

typedef __u64 u64;
typedef __u32 u32;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
} last_departure_map SEC(".maps");

SEC("classifier")
int stob_defense(struct __sk_buff *skb) {
    u64 now = bpf_ktime_get_ns();
    u32 key = 0;
    u64 *last_tstamp = bpf_map_lookup_elem(&last_departure_map, &key);

    u32 jitter = bpf_get_prandom_u32() % 5000000;
    u64 delay = 5000000 + (u64)jitter;
    u64 departure = now + delay;

    if (last_tstamp) {
        if (*last_tstamp + delay > departure) {
            departure = *last_tstamp + delay;
        }
        *last_tstamp = departure;
    }

    skb->tstamp = departure;
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
```

### 2. Session-Level Volume Padding (`mininet/mock_server.py`)
To prevent the attacker from classifying websites using flow volumes, the HTTP server intercepts incoming requests and dynamically appends mock dummy padding to responses, forcing **every single session payload to measure exactly 3 MB** on the wire.

### 3. ML Evaluation Pipeline (`ml_evaluation/`)
We extracted seven robust packet-level features using `Scapy` and `tshark` parser modules:
*   **Volume-Based**: `in_bytes`, `out_bytes`, `in_pkts`, `out_pkts`
*   **Timing-Based**: Mean Inter-Arrival Time (`iat_mean`), IAT Range (`iat_range`), and IAT Median (`iat_median`)

These features are trained and tested using a Scikit-Learn **Random Forest Classifier (k-FP)** configured with 100 estimators in a closed-world setting across 10 target virtual sites.

---

## How to Run the Emulation

### 1. Requirements & Prerequisites
Ensure you are running on a Linux host (or Linux VM) with `clang`, `llvm`, `libbpf-dev`, `mininet`, and Python libraries installed:
```bash
sudo apt update && sudo apt install -y clang llvm libbpf-dev mininet tshark tcpdump python3-pip
pip3 install scapy scikit-learn pandas numpy
```

### 2. Compiling and Loading the eBPF Hook
Compile the egress program using clang:
```bash
clang -g -O2 -target bpf -c ebpf/stob_kern.c -o ebpf/stob_kern.o
```

### 3. Running the Simulation
Execute the network virtualization experiment to generate the PCAP traces and collect baseline vs. defended datasets:
```bash
sudo python3 mininet/run_experiment.py
```

### 4. Running the Classifiers
Evaluate attack surfaces by running the evaluation modules:
```bash
python3 ml_evaluation/train_model1.py
python3 ml_evaluation/eval_cross.py
python3 ml_evaluation/train_model2.py
```

---

## Authors & Context
*   **Aditya Shukla** - IIT Guwahati
*   **Kartik Maheshwari** - IIT Guwahati
*   *Project under the "Reproduction of Empirical Results" track for **CS544: Topics in Networks** (Dr. T. Venkatesh, Jan - May 2026).*
