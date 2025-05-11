import gradio as gr
import json
import requests
import re
import os
import shutil
from datetime import datetime
from analyzer import BinaryAnalyzer
from filefender import FileFender

# -------------------
# Settings & Constants
# -------------------
FOR_ANALYSIS_LATER_DIR = r"D:\polymorphicApplication-improving-analyzer\binaryAnalyzer\for_analysis_later" #change path according to the place 
os.makedirs(FOR_ANALYSIS_LATER_DIR, exist_ok=True)

# ---------------------
# Helper Functions
# ---------------------
def extract_suspicious_strings(strings):
    suspicious = []
    for s in strings:
        if re.search(r'\b\w+\.(exe|dll|bat|sh|py|js|c|cpp)\b', s, re.IGNORECASE) or \
           re.search(r'[a-zA-Z]:\\|/usr/|/bin/|/etc/|/home/|/tmp/', s) or \
           'cmd' in s.lower() or 'powershell' in s.lower() or \
           'malware' in s.lower() or 'payload' in s.lower():
            suspicious.append(s)
        if len(suspicious) >= 20:
            break
    return suspicious

def trim_json(data):
    if "strings" in data:
        data["strings"] = extract_suspicious_strings(data["strings"])
    return data

# ---------------------
# Core Functions
# ---------------------
def analyze_binary(filepath):
    try:
        result = BinaryAnalyzer.analyze(filepath)
        tabs = {k: json.dumps(v, indent=2) if not isinstance(v, str) else v for k, v in result.items()}
        full_output = json.dumps(result, indent=2)

        # Additional features can be added here for more in-depth analysis
        # e.g. entropy, signature database lookup, etc.

        return [
            tabs.get("file_info", ""),
            tabs.get("sections", ""),
            tabs.get("imports", ""),
            tabs.get("exports", ""),
            tabs.get("strings", ""),
            tabs.get("security", ""),
            tabs.get("anomalies", ""),
            tabs.get("pe_specific", ""),
            tabs.get("elf_specific", ""),
            full_output,
            "",  # Placeholder for AI tab
            ""   # Placeholder for VirusTotal
        ]
    except Exception as e:
        return [""] * 10 + [f"Error: {str(e)}", ""]

def for_analysis_later(filepath):
    try:
        filename = os.path.basename(filepath)
        destination = os.path.join(FOR_ANALYSIS_LATER_DIR, f"FOR_ANALYSIS_LATER_{filename}")
        shutil.copy2(filepath, destination)
        return f"✅ File saved for later analysis at: {destination}"
    except Exception as e:
        return f"❌ Failed to save for later analysis: {e}"

def scan_with_virustotal(filepath):
    result = FileFender.scan_file(filepath)
    if not result:
        return "❌ No result returned from VirusTotal."
    if "error" in result:
        return f"❌ VirusTotal Error: {result['error']}"
    return result.get("summary", "⏳ Scan is still in progress or incomplete. Please try again later.")

def download_json(raw_json):
    try:
        path = f"binary_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(path, "w") as f:
            f.write(raw_json)
        return path
    except Exception as e:
        return f"Error saving file: {e}"

# ---------------------
# Gradio UI
# ---------------------
with gr.Blocks(title="Binary Analyzer") as iface:
    gr.Markdown("## 🕵️‍♂️ Binary Analyzer")
    gr.Markdown("Upload a binary to analyze its structure, behavior, and potential threats.")

    with gr.Row():
        file_input = gr.File(label="📂 Upload Binary File", type="filepath")
        analyze_button = gr.Button("🔍 Analyze Binary", variant="primary")

    with gr.Tabs():
        with gr.Tab("📄 File Info"): out_file_info = gr.Textbox(lines=20, label="File Info")
        with gr.Tab("📦 Sections"): out_sections = gr.Textbox(lines=20, label="Sections")
        with gr.Tab("📥 Imports"): out_imports = gr.Textbox(lines=20, label="Imports")
        with gr.Tab("📤 Exports"): out_exports = gr.Textbox(lines=20, label="Exports")
        with gr.Tab("🧵 Strings"): out_strings = gr.Textbox(lines=20, label="Strings")
        with gr.Tab("🔐 Security"): out_security = gr.Textbox(lines=20, label="Security")
        with gr.Tab("🚩 Anomalies"): out_anomalies = gr.Textbox(lines=20, label="Anomalies")
        with gr.Tab("🧬 PE Specific"): out_pe = gr.Textbox(lines=20, label="PE Metadata")
        with gr.Tab("🐧 ELF Specific"): out_elf = gr.Textbox(lines=20, label="ELF Metadata")
        with gr.Tab("📚 Raw JSON Output"): out_raw = gr.Textbox(lines=20, label="Raw JSON")
        with gr.Tab("🧠 AI Analysis"): out_ai = gr.Textbox(lines=20, label="AI Analysis Summary")
        with gr.Tab("🦠 VirusTotal Result"): out_vt = gr.Textbox(lines=25, label="VirusTotal Summary")

    with gr.Row():
        download_button = gr.Button("📥 Download Analysis JSON")
        analysis_later_button = gr.Button("🧱 Save For Analysis Later")
        vt_button = gr.Button("🧪 VirusTotal Scan")

    with gr.Row():
        download_output = gr.File(label="📄 Download Link")
        analysis_later_status = gr.Textbox(label="Save For Analysis Later Status", interactive=False)
        vt_status = gr.Markdown("")

    # Bind actions
    analyze_button.click(
        analyze_binary,
        inputs=file_input,
        outputs=[ 
            out_file_info, out_sections, out_imports, out_exports,
            out_strings, out_security, out_anomalies,
            out_pe, out_elf, out_raw, out_ai, out_vt
        ]
    )

    download_button.click(download_json, inputs=out_raw, outputs=download_output)
    analysis_later_button.click(for_analysis_later, inputs=file_input, outputs=analysis_later_status)
    vt_button.click(scan_with_virustotal, inputs=file_input, outputs=out_vt)

if __name__ == "__main__":
    iface.launch()
