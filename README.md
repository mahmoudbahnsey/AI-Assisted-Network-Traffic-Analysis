<div align="center">

# 🛡️ AI-Assisted Network Traffic Analysis System

### Network Traffic Analysis Powered by Artificial Intelligence

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Scikit-learn](https://img.shields.io/badge/Scikit--learn-1.3.0-orange.svg)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A comprehensive network security system that combines Wireshark for packet capture, Zeek for traffic analysis, and Machine Learning for attack detection with an integrated IDS/IPS.

</div>

---

## 📋 Table of Contents

- [Project Overview](#-project-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Configuration](#-configuration)
- [Machine Learning Models](#-machine-learning-models)
- [Attack Simulation](#-attack-simulation)
- [IDS/IPS System](#-idsips-system)
- [Project Structure](#-project-structure)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🌟 Project Overview

This project provides a comprehensive solution for network traffic analysis and attack detection using advanced techniques:

- **Packet Capture**: Using Wireshark/tshark for real-time network packet capture
- **Deep Analysis**: Integration with Zeek for deep packet inspection and protocol analysis
- **Machine Learning**: Evaluation of multiple models and selection of the best for attack detection
- **Attack Simulation**: DDoS attack simulation for testing and validation
- **Protection**: IDS/IPS system for detecting and blocking malicious traffic

---

## ✨ Features

### 📡 Network Traffic Capture
- Real-time network packet capture using tshark
- BPF filter support for selective capture
- PCAP file conversion to various formats for analysis
- Detailed statistics on captured packets

### 🔍 Zeek Analysis
- Deep packet inspection using Zeek
- Multiple log generation (conn, dns, http, ssl, ssh, smtp)
- Feature extraction from different logs
- Support for custom detection scripts

### 🤠 Machine Learning Models
- **Random Forest**: Random forest classifier
- **Support Vector Machine (SVM)**: Support vector machine
- **XGBoost**: Advanced gradient boosting algorithm
- **Decision Tree**: Decision tree classifier
- **Logistic Regression**: Logistic regression classifier

### 🎯 Attack Detection
- Statistical detection (high packet/byte rates)
- SYN Flood pattern detection
- Port Scanning detection
- ML-based detection

### 🚫 IDS/IPS System
- Automatic blocking of malicious IPs
- Support for Windows Firewall, iptables, and pf
- Connection tracking and rate limiting
- Block duration management

### 💥 Attack Simulation
- SYN Flood Attack
- UDP Flood Attack
- ICMP Flood Attack
- HTTP Flood Attack
- Mixed Attack (combination of attacks)

---

## 🏗️ Architecture

```
┌─────────────────┐
│  Network Traffic │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Wireshark/tshark│  ← Packet Capture
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│      Zeek       │  ← Deep Packet Inspection
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Feature Extraction│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  ML Models      │  ← Attack Detection
│  (RF, SVM, XGB) │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   IDS/IPS       │  ← Attack Blocking
└─────────────────┘
```

---

## ⚙️ Requirements

### Required Software
- **Python**: 3.8 or later
- **Wireshark**: With tshark command-line tool
- **Zeek**: Installed and configured
- **Administrative privileges**: For network capture and firewall rules

### Python Libraries
```
numpy>=1.24.3
pandas>=2.0.3
scikit-learn>=1.3.0
xgboost>=2.0.0
imbalanced-learn>=0.11.0
matplotlib>=3.7.2
seaborn>=0.12.2
scapy>=2.5.0
pyshark>=0.4.6
tqdm>=4.66.1
joblib>=1.3.2
python-dateutil>=2.8.2
```

---

## 📥 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/mahmoudbahney/AI-Assisted-Network-Traffic-Analysis.git
cd AI-Assisted-Network-Traffic-Analysis
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Install Wireshark
- **Windows**: Download and install Wireshark from [wireshark.org](https://www.wireshark.org/download.html)
- **Linux**: `sudo apt-get install wireshark`
- **macOS**: `brew install --cask wireshark`

### 4. Install Zeek
- **Linux**: `sudo apt-get install zeek`
- **macOS**: `brew install zeek`
- **Windows**: Download from [zeek.org](https://zeek.org/download/)

### 5. Verify Installation
```bash
tshark --version
zeek --version
python --version
```

---

## 🚀 Usage

### Capture Network Traffic
```bash
python main.py --mode capture --interface eth0 --duration 60
```

### Analyze PCAP File
```bash
python main.py --mode analyze --input data/raw/capture.pcap
```

### Train ML Models
```bash
python main.py --mode train --training-data data/processed/training_data.csv
```

### Detect Attacks
```bash
python main.py --mode detect --input data/processed/features.csv --model random_forest
```

### Simulate DDoS Attack
```bash
python main.py --mode simulate-ddos --attack-type syn_flood --target 192.168.1.100
```

### Run Full Pipeline
```bash
python main.py --mode full --duration 60 --train --training-data data/processed/training_data.csv
```

---

## ⚙️ Configuration

You can customize the system by editing the `config.py` file:

```python
# Network capture settings
CAPTURE_INTERFACE = "eth0"  # Default network interface
CAPTURE_DURATION = 60       # Capture duration in seconds
PACKET_COUNT = 10000        # Maximum packets to capture

# Zeek settings
ZEEK_PATH = "zeek"          # Path to zeek executable

# IDS/IPS settings
IDS_THRESHOLD = 0.7         # Confidence threshold for detection
BLOCK_DURATION = 300         # IP block duration in seconds

# Model settings
DEFAULT_MODEL = "random_forest"
TEST_SIZE = 0.2
RANDOM_STATE = 42
```

---

## 🤠 Machine Learning Models

### Supported Models

| Model | Description | Advantages |
|---------|-------------|------------|
| Random Forest | Random forest classifier | High accuracy, resistant to overfitting |
| SVM | Support vector machine | Effective in high dimensions |
| XGBoost | Gradient boosting | Excellent performance, fast |
| Decision Tree | Decision tree classifier | Easy to understand and interpret |
| Logistic Regression | Logistic regression | Simple and fast |

### Evaluation Process

1. **Model Training**: Train all models on the data
2. **Evaluation**: Calculate accuracy, precision, recall, F1-score
3. **Selection**: Select the best model based on F1-score
4. **Saving**: Save the best model for later use

### Evaluation Metrics

- **Accuracy**: Percentage of correct classifications
- **Precision**: Ratio of true positives to predicted positives
- **Recall**: Ratio of true positives to actual positives
- **F1-Score**: Harmonic mean of precision and recall
- **ROC-AUC**: Area under the ROC curve

---

## 💥 Attack Simulation

### Supported Attack Types

#### 1. SYN Flood Attack
```bash
python main.py --mode simulate-ddos --attack-type syn_flood --target 192.168.1.100
```
Attack that sends a large number of SYN packets to exhaust server resources.

#### 2. UDP Flood Attack
```bash
python main.py --mode simulate-ddos --attack-type udp_flood --target 192.168.1.100
```
Attack that sends large UDP packets to consume bandwidth.

#### 3. ICMP Flood Attack
```bash
python main.py --mode simulate-ddos --attack-type icmp_flood --target 192.168.1.100
```
Ping flood attack to overwhelm the network with ICMP requests.

#### 4. HTTP Flood Attack
```bash
python main.py --mode simulate-ddos --attack-type http_flood --target 192.168.1.100
```
Application layer attack that sends multiple HTTP requests.

#### 5. Mixed Attack
```bash
python main.py --mode simulate-ddos --attack-type mixed --target 192.168.1.100
```
Combination of different attack types.

---

## 🛡️ IDS/IPS System

### System Components

#### 1. Attack Detector
- **Statistical Detection**: Analyzing packet and byte rates
- **Model-based Detection**: Using machine learning models
- **Anomaly Detection**: Comparison with baseline statistics
- **Connection Tracking**: Monitoring connection rates

#### 2. Attack Blocker
- **IP Blocking**: Automatic blocking of malicious IPs
- **Multi-platform Support**: Windows Firewall, iptables, pf
- **Duration Management**: Temporary blocking with auto-expiry
- **Block Logging**: Saving blocked IP records

### Workflow

```
1. Monitor traffic
   ↓
2. Analyze features
   ↓
3. Detect attacks
   ↓
4. Evaluate confidence
   ↓
5. Block IP (if > threshold)
   ↓
6. Log and report
```

---

## 📁 Project Structure

```
ai-assisted-network-traffic/
├── README.md                 # Documentation file
├── requirements.txt          # Python libraries
├── config.py                 # System configuration
├── main.py                   # Main orchestrator
│
├── capture/                  # Network capture module
│   ├── __init__.py
│   ├── wireshark_capture.py  # Capture using tshark
│   └── packet_parser.py      # Packet parsing using Scapy
│
├── zeek/                     # Zeek integration
│   ├── __init__.py
│   ├── zeek_analyzer.py      # Zeek execution and log generation
│   └── log_parser.py         # Zeek log parsing
│
├── ml/                       # Machine learning module
│   ├── __init__.py
│   ├── preprocessing.py      # Data preprocessing
│   ├── models.py             # ML models
│   └── evaluator.py          # Model evaluation
│
├── ids_ips/                  # IDS/IPS system
│   ├── __init__.py
│   ├── detector.py           # Attack detector
│   └── blocker.py            # Attack blocker
│
├── attacks/                  # Attack simulation
│   ├── __init__.py
│   └── ddos_simulator.py    # DDoS simulation
│
├── data/                     # Data directory
│   ├── raw/                  # Raw PCAP files
│   ├── processed/            # Processed data
│   └── models/               # Trained models
│
└── logs/                     # Log files
    ├── main.log              # System log
    ├── evaluation_results/   # Evaluation results
    └── blocked_ips/          # Blocked IPs
```

---

## 📊 Usage Examples

### Example 1: Capture and Analyze Traffic

```python
from main import NetworkTrafficAnalysisPipeline

# Create pipeline
pipeline = NetworkTrafficAnalysisPipeline()

# Capture traffic
pcap_file = pipeline.capture_traffic(duration=60, interface="eth0")

# Analyze with Zeek
log_files = pipeline.analyze_with_zeek(pcap_file)

# Extract features
features_df = pipeline.parse_zeek_logs(log_files)

# Detect attacks
attacks = pipeline.detect_attacks(features_df)

# Block attackers
blocked_ips = pipeline.block_attackers(attacks)
```

### Example 2: Train and Evaluate Models

```python
# Train models
trained_models = pipeline.train_models(
    data_path="data/processed/training_data.csv",
    target_column="label"
)

# Evaluate models
evaluation_results = pipeline.evaluate_models(
    trained_models=trained_models,
    data_path="data/processed/training_data.csv",
    target_column="label"
)

# Best model
best_model = pipeline.evaluator.best_model
print(f"Best model: {best_model}")
```

### Example 3: Simulate DDoS Attack

```python
# Simulate SYS Flood attack
pcap_file = pipeline.simulate_ddos_attack(
    attack_type="syn_flood",
    packet_count=1000,
    save_pcap=True
)

# Analyze the attack
log_files = pipeline.analyze_with_zeek(pcap_file)
features_df = pipeline.parse_zeek_logs(log_files)
attacks = pipeline.detect_attacks(features_df)
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 Important Notes

### ⚠️ Warnings
- This project is for educational and research purposes only
- Use attack simulation on your own networks only
- Obtain permission before using on any network
- Full responsibility for system usage

### 🔒 Security
- Ensure protection of sensitive log files
- Do not share real network data
- Use anonymized data for training
- Update models regularly

### 🐛 Troubleshooting
- Ensure all requirements are installed
- Check administrative privileges
- Verify Wireshark and Zeek availability
- Review error logs in `logs/main.log`

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 📧 Contact

For questions and inquiries:
- GitHub Issues: [github.com/mahmoudbahney/AI-Assisted-Network-Traffic-Analysis/issues](https://github.com/mahmoudbahney/AI-Assisted-Network-Traffic-Analysis/issues)

---

## 🙏 Acknowledgments
- Wireshark team for the excellent packet capture tool
- Zeek team for the powerful network analysis tool
- Scikit-learn community for the ML library
- All contributors to this project

---

<div align="center">

**If you like this project, don't forget to give it a ⭐ Star on GitHub!**

Made with ❤️ for Network Security

</div>
