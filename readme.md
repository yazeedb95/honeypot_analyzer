Okay, here's the English translation of your README file:

# 🍯 Interactive Honeypot Data Analyzer

An advanced project that combines computer engineering and cybersecurity to create a smart honeypot with advanced data analysis tools.

---

## 📋 Project Description

This project consists of a two-part system:

1.  **Honeypot**: A program that simulates a Telnet service and appears as an easy target for attackers, logging all intrusion attempts.
2.  **Data Analyzer**: An advanced analysis tool that transforms attack data into detailed reports and interactive charts.

---

## 🚀 Key Features

### Honeypot:

-   Realistic Telnet service simulation
-   Detailed logging of all login attempts
-   Capture of usernames and passwords
-   Recording of executed commands
-   Interactive interface with attackers

### Data Analyzer:

-   Comprehensive analysis of intrusion attempts
-   Detailed statistics on attack patterns
-   Interactive charts and graphs
-   Geographical analysis of attack sources
-   Comprehensive security reports
-   Data export in multiple formats

---

## 📦 System Requirements

### Software Requirements:

-   Python 3.7 or newer
-   pip (package manager)

### Required Libraries:

```bash
pandas>=1.5.0
matplotlib>=3.6.0
seaborn>=0.12.0
requests>=2.28.0
numpy>=1.21.0
```

---

## 🛠️ Installation and Setup

### 1. Download the Project

```bash
# Create a project folder
mkdir honeypot_analyzer
cd honeypot_analyzer

# Copy project files into the folder
```

### 2. Install Dependencies

```bash
# Install required libraries
pip install -r requirements.txt

# Or install manually
pip install pandas matplotlib seaborn requests numpy
```

---

## 🚀 Running the Project

### Method 1: Unified Run (Recommended)

```bash
python launcher.py
```

### Method 2: Separate Run

#### Run Honeypot:

```bash
python honeypot_main.py
```

#### Run Data Analyzer:

```bash
python data_analyzer.py
```

---

## 🎯 How to Use

### 1. Start the Honeypot

-   Run the honeypot using port 2323.
-   The honeypot will start listening for incoming connections.
-   All intrusion attempts will be logged in `honeypot_logs.json`.

### 2. Simulate Attacks (for testing)

```bash
# Connect to the honeypot from another machine or locally
telnet localhost 2323

# Or using netcat
nc localhost 2323
```

### 3. Analyze Data

-   Use the data analyzer to analyze the logs.
-   Choose the desired operation from the interactive menu.
-   Get detailed reports and charts.

---

## 📊 Available Analysis Types

### 1. Basic Statistics

-   Total number of interactions
-   Unique IP addresses
-   Activity period
-   Most active attackers

### 2. Login Attempts Analysis

-   Most used usernames
-   Weakest passwords attempted
-   Success/failure rate of login attempts
-   Most common combinations

### 3. Command Analysis

-   Most frequently executed commands
-   Command classification (reconnaissance, file, network, suspicious)
-   Suspicious behavior patterns

### 4. Temporal Analysis

-   Most active times
-   Daily distribution of attacks
-   Weekly activity patterns

### 5. Geographical Analysis

-   Attack sources by country
-   ISP distribution
-   Global attack map

---

## 🛡️ Security Considerations

### Important Warnings:

-   **Do not run the honeypot on the real Telnet port (23)** unless you know what you are doing.
-   Use an isolated environment or a virtual machine for testing.
-   Do not expose the honeypot directly to the internet without proper protection.

### Best Practices:

-   Use port 2323 instead of 23 to avoid conflicts.
-   Monitor resource consumption when running the honeypot.
-   Keep backups of log files.
-   Rotate logs periodically to avoid disk space issues.

---

## 📈 Advanced Features

### Generate Dummy Data

-   Dummy data can be generated to test the analyzer.
-   Includes various attack scenarios.
-   Useful for training and demonstrations.

### Data Export

-   Export to CSV for external analysis.
-   Export reports in text format.
-   Save charts as high-quality images.

### Interactive Interface

-   User-friendly menus.
-   Clear instructional messages.
-   Support for Arabic and English languages.

---

## 🔧 Customization and Development

### Adding New Services

The project can be extended by adding honeypots for other services:

-   FTP Honeypot
-   HTTP/HTTPS Honeypot
-   SSH Honeypot
-   SMTP Honeypot

### Enhancing Analysis

-   Add machine learning algorithms for pattern detection.
-   More advanced analysis of malicious intent.
-   Integration with global threat intelligence databases.

### Improving the Interface

-   Create an interactive web interface.
-   Real-time dashboard.
-   Instant alerts upon threat detection.

---

## 🐛 Troubleshooting

### Common Issues and Solutions:

#### Port Already in Use

```bash
# Find the process using the port
lsof -i :2323

# Kill the process if necessary
kill -9 PID
```

#### Permission Issues

```bash
# Grant execution permissions
chmod +x *.py

# Run with limited privileges (do not use sudo unless absolutely necessary)
```

#### Library Issues

```bash
# Update pip
pip install --upgrade pip

# Reinstall libraries
pip install --force-reinstall -r requirements.txt
```

---

## 📚 Learning Resources

### Important Concepts:

-   **Honeypot**: A decoy system designed to attract attackers.
-   **Network Security**: Securing networks and protecting against intrusions.
-   **Intrusion Detection**: Detecting hacking attempts.
-   **Threat Intelligence**: Security intelligence.

### Further Readings:

-   Linux Security Guide
-   Basic Network Protocols
-   Intrusion Detection Techniques
-   Security Data Analysis

---

## 🤝 Contribution

Contributions to develop the project are welcome:

1.  Fork the project.
2.  Create a new branch for the feature.
3.  Implement changes with documentation.
4.  Send a Pull Request.

### Required Development Areas:

-   Add honeypots for new services.
-   Improve analysis algorithms.
-   Develop a web interface.
-   Translate to additional languages.
-   Enhance performance and security.

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## ✨ Acknowledgements

-   The Python community for the amazing libraries.
-   Developers of open-source security tools.
-   Contributors to the project's development.

---

## 📞 Contact and Support

For any inquiries or issues:

-   Open a new Issue on GitHub.
-   Refer to the Troubleshooting section.
-   Share your experience with the community.

---

**Warning**: This project is designed for educational and research purposes. Use it responsibly and in accordance with local laws.

**Note**: Run the honeypot in a safe and isolated environment to avoid any security risks.