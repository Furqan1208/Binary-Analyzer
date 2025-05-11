import gradio as gr
import json
from analyzer import BinaryAnalyzer

def analyze_binary(file):
    try:
        temp_path = file.name
        result = BinaryAnalyzer.analyze(temp_path)

        # Separate parts of the JSON output for each tab
        tabs = {}

        for key in result:
            content = result[key]
            try:
                tabs[key] = json.dumps(content, indent=2)
            except Exception:
                tabs[key] = str(content)

        return [tabs.get("file_info", ""),
                tabs.get("sections", ""),
                tabs.get("imports", ""),
                tabs.get("exports", ""),
                tabs.get("strings", ""),
                tabs.get("security", ""),
                tabs.get("anomalies", ""),
                tabs.get("pe_specific", ""),
                tabs.get("elf_specific", ""),
                json.dumps(result, indent=2)]  # Raw/full output for last tab

    except Exception as e:
        return [""] * 10 + [f"Error: {str(e)}"]

with gr.Blocks() as iface:
    gr.Markdown("## Binary Analyzer\nUpload a PE or ELF binary file to analyze using LIEF.")
    file_input = gr.File(label="Upload Binary File")

    with gr.Row():
        submit_btn = gr.Button("Analyze")

    with gr.Tabs():
        with gr.Tab("File Info"): out_file_info = gr.Textbox(lines=20, label="File Info")
        with gr.Tab("Sections"): out_sections = gr.Textbox(lines=20, label="Sections")
        with gr.Tab("Imports"): out_imports = gr.Textbox(lines=20, label="Imports")
        with gr.Tab("Exports"): out_exports = gr.Textbox(lines=20, label="Exports")
        with gr.Tab("Strings"): out_strings = gr.Textbox(lines=20, label="Strings")
        with gr.Tab("Security"): out_security = gr.Textbox(lines=20, label="Security Checks")
        with gr.Tab("Anomalies"): out_anomalies = gr.Textbox(lines=20, label="Anomalies")
        with gr.Tab("PE Specific"): out_pe = gr.Textbox(lines=20, label="PE-Specific")
        with gr.Tab("ELF Specific"): out_elf = gr.Textbox(lines=20, label="ELF-Specific")
        with gr.Tab("Raw Output"): out_raw = gr.Textbox(lines=20, label="Full JSON Output")

    submit_btn.click(
        analyze_binary,
        inputs=file_input,
        outputs=[out_file_info, out_sections, out_imports, out_exports, out_strings,
                 out_security, out_anomalies, out_pe, out_elf, out_raw]
    )

if __name__ == "__main__":
    iface.launch()
