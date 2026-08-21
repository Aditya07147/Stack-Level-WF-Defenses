# Stack-Level Website Fingerprinting Defenses (Stob)

An end-to-end empirical replication of **Stob (Stack-level Traffic Obfuscation)**—originally proposed in ACM HotNets '25—to close the *Application-Stack Gap* in Website Fingerprinting (WF) defenses. This project validates how moving obfuscation primitives directly into the Linux kernel prevents standard TCP optimizations from stripping away privacy-focused delays and padding.

---

## 📁 Repository Structure

The project is structured logically into standalone pipelines:

```text
├── docs/                                     # Academic deliverables and reference literature
│   ├── CS544_Course_Project_Presentation.pdf # Class presentation slides (PDF)
│   ├── CS544_Course_Project_Report.pdf       # Complete academic project report (PDF)
│   └── Research_Paper.pdf                    # Reference HotNets '25 "Stob" research paper (PDF)
├── ebpf/
│   └── stob_kern.c                           # eBPF C program to inject TC egress timing jitter
├── mininet/
│   ├── generate_sites.py                     # Script to populate mock websites with unique sizes
│   ├── mock_server.py                        # Python server serving 10 sites with dynamic 3MB padding
│   └── run_experiment.py                     # Virtual network topology, data collection, and traffic capture
└── ml_evaluation/
    ├── train_model1.py                       # Trains baseline classifier on undefended traffic (100.00% accuracy)
    ├── eval_cross.py                         # Evaluates Model 1 on defended traffic (10.00% random chance baseline)
    └── train_model2.py                       # Trains adaptive classifier on defended traffic (60.00% accuracy)

🧠 Background & Motivation

1. Website Fingerprinting & The Encryption Paradox

While modern cryptographic protocols like TLS 1.3 and QUIC successfully secure
the plaintext payload of network communications, they leave side-channel
metadata exposed. Passive network observers, such as ISPs or national censorship
firewalls, can apply Deep Learning classifiers (e.g., k-FP, Var-CNN) to packet
sizes, directions, and inter-arrival times (IAT) to construct unique website
"fingerprints".

With the industry-wide rollout of Encrypted Client Hello (ECH), even the Server
Name Indication (SNI) is encrypted, hiding the destination domain entirely.
Consequently, traffic analysis of metadata remains the last viable vector for
state censors to identify visited websites.

2. The "Application-Stack Gap" (Why App-Level Defenses Fail)

Historically, WF countermeasures (e.g., FRONT, WTF-PAD, BuFLO) have been
implemented at the application layer (inside browsers or web servers). The
original paper establishes that these defenses are fundamentally "broken" by the
host operating system's network stack:

  - Asynchronous Send Buffering: Application writes (send()) are copied to
    socket buffers and transmitted based on TCP ACK-clocking and congestion
    window (cwnd) availability, ignoring precise timing requested by the
    application.
  - Packet Coalescing: To minimize CPU and header overhead, the kernel's TCP
    layer combines multiple small, obfuscated application writes into single,
    large maximum transmission unit (MTU) packets.
  - TSO (TCP Segmentation Offload): The NIC hardware splits large segments into
    MSS-sized packets at line rate without interleaving, destroying
    application-level delay scheduling.
  - Inefficient Padding Overhead: Lacking fine-grained control over timing,
    app-level defenses resort to heavy dummy padding, introducing unsustainable
    bandwidth overheads (e.g., 80% in FRONT and up to 309% in QCSD).

3. The Stob Paradigm: Stack-Level Enforcement

To bridge this gap, the authors of Stob propose moving traffic obfuscation
directly into the host network stack (spanning the transport and packet I/O
layers). Operating at the kernel level gives the defense the "final say" over
packet sequences.

Using lightweight kernel technologies like eBPF (Extended Berkeley Packet
Filter), applications can push privacy policies (e.g., pacing histograms) to a
shared kernel map. This allows the stack to perform microsecond-level timing
modifications and dynamic packet sizing on the wire, natively cooperating with
Congestion Control Algorithms (CCA) and queuing disciplines (qdisc).

🛠️ System Architecture & Implementation

Our implementation targets the two core traffic leaks analyzed by website
fingerprinting attacks: packet timing (Inter-Arrival Time) and session volume
(byte counts).

1. Timing Obfuscation via eBPF (ebpf/stob_kern.c)

To bypass stack-level optimizations like Packet Coalescing and TCP Segmentation
Offload (TSO), we implemented timing obfuscation directly in kernel space.

Our C program attaches to the Traffic Control (TC) egress hook of the interface.
When a packet reaches this hook, we modify its departure timestamp
(skb->tstamp). The Fair Queuing (FQ) qdisc then holds the packet until this
exact scheduled time, ensuring precise wire-level obfuscation:

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

typedef __u64 u64;
typedef __u32 u32;

SEC("classifier")
int stob_defense(struct __sk_buff *skb) {
    u64 now = bpf_ktime_get_ns();

    // Inject a base delay of 5ms + random jitter of 0-5ms (5,000,000 nanoseconds)
    u32 jitter = bpf_get_prandom_u32() % 5000000;
    u64 delay = 5000000 + (u64)jitter;

    skb->tstamp = now + delay;
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

2. Session-Level Volume Padding (mininet/mock_server.py)

To prevent the attacker from classifying websites using flow volumes, the HTTP
server intercepts incoming requests and dynamically appends mock dummy padding
to responses, forcing every single session payload to measure exactly 3 MB on
the wire.

3. ML Evaluation Pipeline (ml_evaluation/)

We extracted seven robust packet-level features using tshark parser modules:

  - Volume-Based: in_bytes, out_bytes, in_pkts, out_pkts
  - Timing-Based: Mean Inter-Arrival Time (iat_mean), IAT Range (iat_range), and
    IAT Median (iat_median)

These features are trained and tested using a Scikit-Learn Random Forest
Classifier (k-FP) configured with 100 estimators in a closed-world setting
across 10 target virtual sites.

📊 Experimental Results

| Model / Evaluation Phase            | Accuracy    | Findings & Observations                                                                                                                                                                 |
| ----------------------------------- | :---------: | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Model 1: Clean Baseline**         | **100.00%** | In an undefended standard Linux stack, metadata (burst sizes, raw pacing, volumes) completely leaks site identities onto the wire.                                                      |
| **Cross-Evaluation (Clean ➔ Stob)** | **10.00%**  | Applying Model 1 on Stob-defended traces renders the model useless, dropping classification performance to pure random chance (1/10).                                                   |
| **Model 2: Adaptive Attacker**      | **60.00%**  | Training a new classifier directly on defended traffic recovers some signature for multi-object sites (5 or 10 requests), but the defense still degrades overall identification by 40%. |

🚀 How to Run the Emulation

1. Requirements & Prerequisites

Ensure you are running on a Linux host (or WSL2) with necessary dependencies
installed:

sudo apt update && sudo apt install -y clang llvm libbpf-dev mininet tshark tcpdump python3-pip python3-pandas python3-sklearn python3-scapy

2. Generating Sites & Compiling eBPF

python3 mininet/generate_sites.py
clang -g -O2 -target bpf -c ebpf/stob_kern.c -o stob_kern.o

3. Running the Simulation

Execute the network virtualization experiment to generate the PCAP traces:

sudo python3 mininet/run_experiment.py

4. Running the Classifiers

Evaluate attack surfaces by running the evaluation modules:

python3 ml_evaluation/train_model1.py
python3 ml_evaluation/eval_cross.py
python3 ml_evaluation/train_model2.py


---
