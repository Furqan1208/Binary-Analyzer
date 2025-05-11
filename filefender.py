import hashlib
import requests
import os

VIRUSTOTAL_API_KEY = ""  # 🔐 Replace with your actual API key
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files"

class FileFender:
    @staticmethod
    def scan_file(file_path):
        """Check file hash on VirusTotal."""
        try:
            if not os.path.exists(file_path):
                return {"error": "📁 File not found."}

            # Compute SHA256 hash
            with open(file_path, "rb") as f:
                sha256_hash = hashlib.sha256(f.read()).hexdigest()

            headers = {
                "x-apikey": VIRUSTOTAL_API_KEY,
                "accept": "application/json"
            }

            response = requests.get(f"{VIRUSTOTAL_API_URL}/{sha256_hash}", headers=headers, timeout=15)
            response.raise_for_status()

            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            total = sum(stats.values())
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            score = (malicious + suspicious) / total * 100 if total else 0

            detection_engines = data.get("last_analysis_results", {})
            detections = [
                f"- **{engine}**: {details.get('result')}"
                for engine, details in detection_engines.items()
                if details.get("category") in ["malicious", "suspicious"]
            ]
            detection_summary = "\n".join(detections) if detections else "✅ No malicious or suspicious detections."

            summary = f"""
### 🧪 File Hash Scan Summary

**SHA256**: `{sha256_hash}`  
**Total Engines Scanned**: {total}  
**Malicious Detections**: {malicious}  
**Suspicious Detections**: {suspicious}  
**Overall Risk Score**: {score:.2f}%

---

### 🛡️ Detected Threats by Engines
{detection_summary}
            """.strip()

            return {"summary": summary}

        except Exception as e:
            return {"error": f"VirusTotal lookup failed: {str(e)}"}
