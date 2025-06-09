# 🛡️ Binary Analyzer - Malware Detection Framework

**Institution:** NED University of Engineering & Technology – CSIT Department  

---

## 📌 Project Title

**Malware Analyzer – A Modular Binary Analysis Framework Using Python**

---

## 👥 Group Members

- Furqan Patel     
- Tayyab Qamar     
- Anum Mateen    
- Hamza Riaz      

---

## 📝 Project Description

This project presents a comprehensive binary analysis framework for malware inspection using the **LIEF** library in Python. It offers **modular**, **scalable**, and **automated** tools to analyze executable files, primarily Portable Executables (PE). This framework is designed for cybersecurity researchers, malware analysts, and digital forensics teams to extract, inspect, and report on critical malware characteristics from binary samples.

The analyzer identifies:
- Suspicious imports and strings
- Anti-debugging techniques
- Digital certificate presence
- Packing/encryption indicators
- Section entropy
- Export anomalies
- Static signatures using VirusTotal

---

## 🛠️ Tools and Libraries Used

- **Python 3.11+**
- **LIEF** – Library to Instrument Executable Formats
- `hashlib`, `json`, `re`, `os`, `logging` – For support operations
- **VirusTotal Public API** – For signature validation
- `Gradio` – For simple web-based UI (optional)

---

## 🗂️ Module Overview

Each feature is implemented as a standalone script inside the `/utils` directory:

- `AnomalyFinder.py`: Detects obfuscation and suspicious strings
- `AntiDebugChecker.py`: Checks for anti-debugging markers
- `ArchitectureAnalyzer.py`: Identifies 32-bit or 64-bit binaries
- `CertificateChecker.py`: Verifies digital signatures
- `EntropyCalculator.py`: Analyzes entropy for potential packing
- `ExportAnalyzer.py`: Checks exported symbols and functions
- `HashGenerator.py`: Computes MD5, SHA1, SHA256
- `ImportAnalyzer.py`: Highlights suspicious API calls
- `PackersDetector.py`: Detects common packers like UPX
- `PEiDAnalyzer.py`: Matches PE signatures (like PEiD)
- `ResourceAnalyzer.py`: Extracts embedded resources
- `SectionEntropyChecker.py`: Compares entropy across sections
- `SignatureChecker.py`: Compares binaries with known malware strings

---

## ▶️ How to Run

1. **Clone the repository:**

```bash
git clone https://github.com/Furqan1208/Binary-Analyzer.git
cd Binary-Analyzer
```

2. **Install required dependencies:**

```bash
pip install -r requirements.txt
```

Run analysis:

To analyze a binary:

```bash
python analyzer.py path/to/binary.exe
```

Optionally, run the web app (if Gradio UI is enabled), before running add virustotal api in file fender:

```bash
python app.py #vithout virus total
python newapp.py # with virustotal
```

## 🔍 VirusTotal Integration
The framework integrates with the VirusTotal Public API to cross-validate binary hashes and fetch reputation reports.
Ensure your API key is set in a .env or config file:

```bash
VT_API_KEY=your_virustotal_api_key
```

## 📸 Screenshots
Screenshots are in SS folder


## 📁 Project Structure
```bash
Binary-Analyzer/
│
├── analyzer.py                # Entry-point script
├── app.py                     # Optional Gradio web UI
├── filefender.py              # File handling
├── utils/                     # Modular analyzers
├── for_analysis_later/       # Quarantined files
├── binary_analysis_*.json    # Generated reports
├── .gradio/flagged/          # UI test logs
└── README.md                 # This file
```

## 🔄 Future Enhancements
- Support for ELF and Mach-O formats
- Dynamic Analysis using sandbox or emulation
- Web dashboard for result aggregation
- YARA/ML-based detection improvements

## 📚 References
- LIEF Documentation
- Microsoft PE Format
- Malware Unicorn RE Course
- NIST Cybersecurity
