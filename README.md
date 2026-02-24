# IntrusionDetectionSystemIDS

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-Experimental-orange.svg)

An advanced, modular Intrusion Detection System (IDS) that monitors network traffic and detects anomalous behavior or patterns indicating potential attacks (e.g., DDoS, Port Scans, SYN Floods).

It performs packet capture and analysis using **Scapy** and supports a dual-engine detection approach:

1. **Rule-Based Detection:** Statistical baseline and deviation analysis.
2. **Machine Learning Anomaly Detection:** Behavioral learning using Isolation Forest.

---

## Table of Contents

- [ Project Overview](#-project-overview)
- [ Architecture](#️-architecture)
- [ Detection Approaches](#-detection-approaches)
- [1. Rule-Based IDS](#1️⃣-rule-based-ids)
- [2. Machine Learning IDS](#2️⃣-machine-learning-ids)
- [3. Temporal Flow Aggregation](#3️⃣-temporal-flow-aggregation-5s-windows)
- [Getting Started](#️-getting-started)
- [Testing Attacks](#-testing-attacks)
- [Model Persistence](#-model-persistence)
- [Future Improvements](#-future-improvements)
- [License](#-license)

---

## Project Overview

This system is built with a strong emphasis on modularity, scalability, and clean separation of responsibilities. Key capabilities include:

- **Live Traffic Capture:** Real-time packet interception.
- **Feature Extraction:** Translating raw packets into actionable numeric vectors.
- **Dynamic Baselines:** Learning standard network behavior on the fly.
- **Threat Detection:** Identifying DDoS, Port Scans, and SYN floods.
- **Flow Aggregation:** Grouping packets into 5-second windows to detect subtle, distributed attacks.
- **Persistent ML:** Logging alerts and saving ML models for continuous learning.

---

## Architecture

The codebase follows a strict `src/` layout, using absolute imports and separating data extraction from detection logic.

```text
IntrusionDetectionSystemIDS/
├── src/
│ └── main/
│ ├── base/
│ │ ├── __init__.py
│ │ └── baseline_dynamic_store.py
│ ├── data/
│ │ ├── __init__.py
│ │ └── packet_capture.py
│ ├── examples/
│ │ ├── __init__.py
│ │ └── mini_ids.py
│ ├── features/
│ │ ├── __init__.py
│ │ ├── packet_feature_extractor.py
│ │ └── packet_vectorizer.py
│ ├── logs/
│ │ ├── __init__.py
│ │ └── alert_logger.py
│ ├── models/
│ │ ├── __init__.py
│ │ ├── ml_model_config.py
│ │ └── ml_model_persistence.py
│ ├── rules/
│ │ ├── __init__.py
│ │ ├── rules_detection_engine.py
│ │ └── ml_detection_engine.py
│ ├── windows/
│ │ ├── __init__.py
│ │ └── traffic_window_aggregator.py
│ ├── __init__.py
│ └── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

## Detection Approaches

### 1. Rule-Based IDS

Builds a **dynamic baseline** during a warm-up period and flags anomalies based on statistical deviation.

| Attack Type   | Detection Logic               | Base Metrics Monitored                           |
| ------------- | ----------------------------- | ------------------------------------------------ |
| **DDoS**      | `PPS > μ + 3σ`                | Packets per second (PPS), Bytes per second (BPS) |
| **Port Scan** | `Unique ports > μ + 3σ`       | Unique destination ports per source IP           |
| **SYN Flood** | Excessive `SYN` without `ACK` | TCP flag behavior                                |

> 📍 _Implementation details found in:_ `main/rules/rules_detection_engine.py`

### 2. Machine Learning IDS

Instead of hardcoded thresholds, the ML engine uses an **Isolation Forest** model to learn "normal" traffic.

**Vectorization Process:** Each packet is transformed into a 12-dimensional numeric vector including: _Packet length, Protocol number, Source/Destination ports, TCP flags, Window size, TTL, Fragment ID, Payload length, Inter-arrival time, Payload entropy, and Same-source frequency._

> 📍 _Feature extraction:_ `main/features/packet_vectorizer.py` 📍 _Detection engine:_ `main/rules/ml_detection_engine.py`

### 3. Temporal Flow Aggregation (5s Windows)

Groups packets into 5-second flow windows based on `(proto, src_ip, dst_ip, dst_port)`. This is crucial for identifying:

- Slow scans

- Distributed UDP floods

- Low-rate intrusion attempts

> 📍 _Implementation details found in:_ `main/windows/traffic_window_aggregator.py`

---

## Getting Started

### Prerequisites

- Python 3.8+

- Linux environment recommended (root privileges required for raw packet capture).

### Installation

1.**Clone the repository and set up a virtual environment:**

```Bash
python -m venv .venv
```

2.**Activate the virtual environment:**

- **Windows:**

```Bash
.venv\Scripts\activate
```

- **Linux/macOS:**

```Bash
source .venv/bin/activate
```

3.**Install dependencies:**

```Bash
pip install -r src/main/requirements.txt
```

_Main packages: `scapy`, `numpy`, `pyod`, `scikit-learn`, `joblib`_

### Running the IDS

_Note: You may need to run these scripts with `sudo` or administrator privileges to allow network interface capture._

**Run Rule-Based Example:**

```Bash
sudo python src/main/examples/mini_ids.py
```

**Run ML-Based Detection:**

```Bash
sudo python src/main/rules/ml_detection_engine.py
```

_The system will automatically collect packets, train the model, begin detection, and write alerts to `main/logs/alert_logger.py`._

---

## Testing Attacks

You can verify the IDS functionality by simulating attacks using external tools like `hping3` and `nmap`.

**Simulate SYN Flood:**

```Bash
sudo hping3 -S -p 80 --flood <target-ip>
```

**Simulate UDP Flood:**

```Bash
sudo hping3 --udp --flood <target-ip>
```

**Simulate Port Scan:**

```Bash
nmap -sS <network-range>
```

---

## Model Persistence

The ML architecture supports continuous learning. Models can be saved and reloaded via `main/models/ml_model_persistence.py`. This ensures:

- Model reuse after system restarts.

- Long-term anomaly memory.

- Reduced training overhead on subsequent runs.

---

## Design Principles

- **Clear Separation:** Modular detection engines independent of capture and configuration logic.

- **Extensible Architecture:** Designed to easily plug in advanced neural networks (LSTM, Seq2Seq, etc.).

## Future Improvements

- \[ \] LSTM Autoencoder implementation

- \[ \] Seq2Seq + Attention mechanisms

- \[ \] Real-time visualization dashboard

- \[ \] Automatic firewall blocking integration

- \[ \] Flow export to Elastic/Prometheus

- \[ \] GPU-accelerated ML

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Authors <a name = "authors"></a>

- [@Kerlon Amaral](https://github.com/RobotEby) - Idea & Initial work

See also the list of [contributors](https://github.com/RobotEby/TheDarkMark/contributors) who participated in this project.
