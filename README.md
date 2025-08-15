# Advanced-Network-Security-Analyzer
Enterprise-grade network packet analyzer with real-time threat detection and security monitoring
# 🛡️ Advanced Network Security Analyzer - Enterprise Edition

[![Windows](https://img.shields.io/badge/Windows-Supported-green)](https://github.com/munircse1995/Advanced-Network-Security-Analyzer)
[![Kali Linux](https://img.shields.io/badge/Kali_Linux-Supported-green)](https://github.com/munircse1995/Advanced-Network-Security-Analyzer)
[![macOS](https://img.shields.io/badge/macOS-Supported-green)](https://github.com/munircse1995/Advanced-Network-Security-Analyzer)

Professional-grade network security monitoring tool with real-time threat detection, packet analysis, and security forensics capabilities.

![Screenshot](docs/images/dashboard-preview.png)

---

## 🚀 Key Features
- **Real-time Packet Analysis** – Capture and inspect network traffic
- **Threat Intelligence** – Detect port scans, DDoS attempts, and malware signatures
- **Security Dashboard** – Visualize threats with severity levels
- **GeoIP Tracking** – Identify geographic locations of traffic sources
- **Professional Reporting** – Export to CSV/JSON for forensic analysis
- **Cross-Platform** – Runs on **Windows**, **Linux (Kali)**, and **macOS**

---

## 📥 Installation

### **Windows**
1. Download the [latest release](https://github.com/munircse1995/Advanced-Network-Security-Analyzer/releases)
2. Extract the ZIP file to a folder (e.g., `C:\NetworkAnalyzer`)
3. Run `CreateShortcut.bat` to create a desktop shortcut
4. Double-click **"Network Security Analyzer"** (runs as Administrator)

### **Linux / Kali**
```bash
sudo apt update
sudo apt install python3-pip git -y
git clone https://github.com/munircse1995/Advanced-Network-Security-Analyzer.git
cd Advanced-Network-Security-Analyzer
sudo python3 src/network_analyzer.py
macOS
bash
Copy
Edit
# Install Homebrew (if not installed)
 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python

# Clone repository
git clone https://github.com/munircse1995/Advanced-Network-Security-Analyzer.git
cd Advanced-Network-Security-Analyzer

# Run analyzer
sudo python3 src/network_analyzer.py
🖥️ Usage
Launch the application

Click "START CAPTURE" to begin analysis

Use filters to focus on specific traffic

View threats in the Security Dashboard

Export data via "EXPORT CSV/JSON"


⚙️ Technical Specifications
Languages: Python 3.7+

Database: SQLite for persistent storage

Security: Malware signature detection with 50+ patterns

Dependencies

bash
Copy
Edit
# Windows
pip install psutil pywin32 pyshark

# Linux/macOS
pip install psutil pyshark
🤝 Contribution
We welcome contributions!

Fork the repository

Create your feature branch:

bash
Copy
Edit
git checkout -b feature/amazing-feature
Commit changes:

bash
Copy
Edit
git commit -m "Add amazing feature"
Push to branch:

bash
Copy
Edit
git push origin feature/amazing-feature
Open a pull request

📜 License
This project is licensed under the GNU GPL v3.0 – see the LICENSE file for details.

👨‍💻 Developer
Shirajam Munir Fahad
