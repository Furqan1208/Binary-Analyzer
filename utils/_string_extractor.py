import lief
from typing import Dict, List, Optional

from ._section_analyzer import SectionAnalyzer

class StringExtractor:
    @staticmethod
    def _extract_strings(binary: lief.Binary, min_length: int = 4, sections: Optional[List[Dict]] = None) -> List[str]:
        """Extract ASCII strings from binary sections (pass pre-computed sections)"""
        strings = []
        # Use passed sections if available, otherwise re-analyze (less efficient)
        if sections is None:
             sections = SectionAnalyzer._analyze_sections(binary)
        if not sections: # If still no sections (e.g. no attribute or error)
             return strings

        for section_info in sections:
             # Get section object from binary using name/offset if needed, or assume direct iteration works
             # Note: Relying on direct iteration of binary.sections is often easier
             section = None
             if hasattr(binary, 'get_section'):
                  section = binary.get_section(section_info['name'])
             # Fallback: Iterate binary.sections and match name/offset if get_section fails/missing
             if not section and hasattr(binary, 'sections'):
                  for s in binary.sections:
                       if getattr(s,'name',None) == section_info['name'] and getattr(s,'offset',-1) == int(section_info['offset'],16):
                           section = s
                           break
             if not section: continue # Skip if section object can't be retrieved

             # Check flags from the pre-computed section_info dictionary
             flags = section_info.get("flags", {})
             is_exec = flags.get("executable", False)
             entropy = section_info.get("entropy", 0.0)
             size = section_info.get("size", 0)

             if size == 0 or (is_exec and entropy > 6.0):
                 continue

             try:
                 # Ensure section content can be accessed
                 if hasattr(section, 'content'):
                      data = bytes(section.content)
                 else: continue # Skip if content cannot be accessed

                 current_str = []
                 for byte in data:
                     if 32 <= byte <= 126: # Printable ASCII
                         current_str.append(chr(byte))
                     else:
                         if len(current_str) >= min_length:
                             strings.append(''.join(current_str))
                         current_str = []
                 if len(current_str) >= min_length: # Tail end
                     strings.append(''.join(current_str))
             except Exception: # Catch errors during content access or processing
                 continue

        return list(Dict.fromkeys(strings))

