from typing import Dict, Any
import traceback
import argparse
import sys
import os
import json
import lief

from utils._architecture_analyzer import ArchitectureAnalyzer
from utils._section_analyzer import SectionAnalyzer
from utils._import_analyzer import ImportAnalyzer
from utils._export_analyzer import ExportAnalyzer
from utils._packer_detector import PackerDetector
from utils._certificate_checker import CertificateChecker
from utils._anti_debug_checker import AntiDebugChecker
from utils._relro_checker import RelroChecker
from utils._string_extractor import StringExtractor
from utils._anomaly_finder import AnomalyFinder
from utils._pe_analyzer import PEAnalyzer
from utils._elf_analyzer import ELFAnalyzer

class BinaryAnalyzer:
    @staticmethod
    def analyze(file_path: str) -> Dict[str, Any]:
        try:
            raw_file_size = os.path.getsize(file_path)
            with open(file_path, 'rb') as f:
                binary = lief.parse(f.read())

            if not binary:
                raise ValueError("Failed to parse binary file (lief.parse returned None)")

            architecture = ArchitectureAnalyzer._get_architecture(binary)
            image_size = binary.optional_header.sizeof_image if isinstance(binary, lief.PE.Binary) and hasattr(binary, 'optional_header') else None

            sections = SectionAnalyzer._analyze_sections(binary)
            imports = ImportAnalyzer._get_imports(binary)
            exports = ExportAnalyzer._get_exports(binary)
            security_checks = {
                 "packer": PackerDetector._detect_packer(binary, sections=sections),
                 "certificates": CertificateChecker._check_certificates(binary),
                 "anti_debug": AntiDebugChecker._check_anti_debug(binary, imports=imports),
                 "nx_bit": getattr(binary, 'has_nx', None),
                 "relro": RelroChecker._check_relro(binary)
            }

            result = {
                "file_info": {
                    "path": file_path,
                    "raw_size_bytes": raw_file_size,
                    "format": str(binary.format),
                    "architecture": architecture,
                    "entrypoint": hex(binary.entrypoint),
                    "is_pie": getattr(binary, 'is_pie', False),
                    "image_size_bytes": image_size,
                },
                "sections": sections,
                "imports": imports,
                "exports": exports,
                "strings": StringExtractor._extract_strings(binary, sections=sections),
                "security": security_checks,
                "anomalies": AnomalyFinder._find_anomalies(binary, sections=sections, imports=imports, security_checks=security_checks)
             }

            if isinstance(binary, lief.PE.Binary):
                result["pe_specific"] = PEAnalyzer._analyze_pe(binary)
            elif isinstance(binary, lief.ELF.Binary):
                result["elf_specific"] = ELFAnalyzer._analyze_elf(binary)

            return result

        except ValueError as e:
             return {"error": str(e), "file": file_path}
        except IOError as e:
             return {"error": f"File system error: {e}", "file": file_path}
        except Exception as e:
            return {"error": f"An unexpected error occurred: {type(e).__name__} - {e}", "traceback": traceback.format_exc(), "file": file_path}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze PE/ELF binary files for malware indicators using LIEF.")
    parser.add_argument("binary_path", help="Path to the binary file to analyze.")
    parser.add_argument("-o", "--output", help="Optional path to save the JSON results to a file.")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    analysis_result = BinaryAnalyzer.analyze(args.binary_path)
    json_output = json.dumps(analysis_result, indent=2, default=str)

    if args.output:
        try:
            with open(args.output, 'w') as f: f.write(json_output)
            print(f"Analysis results saved to: {args.output}")
        except IOError as e:
            print(f"Error writing output file: {e}", file=sys.stderr)
            print("\nAnalysis Results:\n", json_output)
    else:
        print(json_output)