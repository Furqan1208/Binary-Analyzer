import lief
from typing import Dict, List, Optional, Any

from ._section_analyzer import SectionAnalyzer


class PackerDetector:
    
    @staticmethod
    def _detect_packer(binary: lief.Binary, sections: Optional[List[Dict]] = None) -> Optional[str]:
        """Detect common packers/compilers (pass pre-computed sections)"""
        # Use passed sections if available
        if sections is None:
             sections = SectionAnalyzer._analyze_sections(binary)

        packer_signatures = { #... keep signatures ...
             "UPX": [b"UPX0", b"UPX1", b"UPX!"],
             "FSG": [b"FSG!", b"FSG Protector"],
             "PECompact": [b"PECompact"],
             "ASPack": [b"ASPack"],
             "Themida/WinLicense": [b"Themida", b"WinLicense"],
             "VMProtect": [b"VMProtect"],
             "Enigma Protector": [b"Enigma"],
             "MoleBox": [b"MoleBox"],
        }

        # 1. Check section names (using pre-computed section data)
        section_names = [s.get('name', '').lower() for s in sections]
        for name, patterns in packer_signatures.items():
             for pattern_bytes in patterns:
                  try:
                      pattern_str = pattern_bytes.decode('ascii', errors='ignore').lower()
                      if not pattern_str: continue

                      # Specific checks first
                      if name == "UPX" and Any(s_name in ['upx0', 'upx1'] for s_name in section_names): return "UPX"
                      if name == "VMProtect" and Any(s_name.startswith('.vmp') for s_name in section_names): return "VMProtect"

                      # General pattern check in names (avoid short generic patterns)
                      if len(pattern_str) > 2 and Any(pattern_str in s_name for s_name in section_names):
                          return name
                  except Exception: continue # Ignore decoding errors


        # 2. Check header data (as before)
        try:
            header_data = b""
            if hasattr(binary, 'original_bytes'):
                 header_data = bytes(binary.original_bytes[:1024])
            elif hasattr(binary, 'input_filepath'): # Re-read if no original_bytes
                 with open(binary.input_filepath, 'rb') as f: header_data = f.read(1024)

            if header_data:
                for name, patterns in packer_signatures.items():
                    for pattern in patterns:
                        if pattern in header_data: return name
        except Exception: pass # Ignore errors reading header


        # 3. Check entropy (using pre-computed section data)
        entry_point_addr = getattr(binary, 'entrypoint', 0)
        entry_point_section_info = None
        first_section_info = sections[0] if sections else None

        # Find entry point section info from the List
        if entry_point_addr > 0:
             for s_info in sections:
                  start = int(s_info['virtual_address'], 16)
                  size = s_info['size']
                  if start <= entry_point_addr < start + size:
                      entry_point_section_info = s_info
                      break

        if entry_point_section_info and entry_point_section_info.get('entropy', 0.0) > 7.5:
             return f"Likely Packed (High Entropy at Entry Point: {entry_point_section_info['entropy']:.2f})"
        elif first_section_info and first_section_info.get('entropy', 0.0) > 7.5:
             return f"Likely Packed (High Entropy in First Section: {first_section_info['entropy']:.2f})"

        return None

 