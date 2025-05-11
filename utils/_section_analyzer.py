import lief
from typing import Dict, List



class SectionAnalyzer:
    @staticmethod
    def _analyze_sections(binary: lief.Binary) -> List[Dict]:
        """Analyze binary sections with security flags (Handles PE/ELF)"""
        sections = []
        if not hasattr(binary, 'sections'):
             return sections

        for section in binary.sections:
            section_data = {
                "name": getattr(section, 'name', ""), # Use getattr for safety
                "virtual_address": hex(getattr(section, 'virtual_address', 0)),
                "size": getattr(section, 'size', 0),
                "offset": hex(getattr(section, 'offset', 0)),
                "entropy": 0.0,
                "flags": {},
                "suspicious": False
            }

            try:
                section_data["entropy"] = round(section.entropy, 4)
            except Exception:
                 section_data["entropy"] = -1.0 # Indicate error

            # --- ELF Section Flags ---
            if isinstance(binary, lief.ELF.Binary) and isinstance(section, lief.ELF.Section):
                # Use section.has_flag where possible (might be newer API) or direct access
                try:
                    is_exec = section.has(lief.ELF.Section.FLAGS.EXECINSTR) if hasattr(lief.ELF.Section, 'FLAGS') else bool(section.flags & lief.ELF.SECTION_FLAGS.EXECINSTR)
                    is_write = section.has(lief.ELF.Section.FLAGS.WRITE) if hasattr(lief.ELF.Section, 'FLAGS') else bool(section.flags & lief.ELF.SECTION_FLAGS.WRITE)
                    is_alloc = section.has(lief.ELF.Section.FLAGS.ALLOC) if hasattr(lief.ELF.Section, 'FLAGS') else bool(section.flags & lief.ELF.SECTION_FLAGS.ALLOC)
                    section_data["flags"] = {
                        "executable": is_exec, "writable": is_write, "allocatable": is_alloc,
                        "raw_flags": hex(getattr(section, 'flags', 0))
                    }
                    section_data["suspicious"] = is_exec and is_write
                except AttributeError: # Handle if SECTION_FLAGS is also missing
                     section_data["flags"] = {"error": "Could not read ELF flags", "raw_flags": hex(getattr(section, 'flags', 0))}

            elif isinstance(binary, lief.PE.Binary) and isinstance(section, lief.PE.Section):
                try:
                    # Standard PE section characteristics from Microsoft PE/COFF specification
                    MEM_EXECUTE = 0x20000000
                    MEM_WRITE = 0x80000000
                    MEM_READ = 0x40000000
                    
                    characteristics = section.characteristics
                    is_exec = bool(characteristics & MEM_EXECUTE)
                    is_write = bool(characteristics & MEM_WRITE)
                    is_read = bool(characteristics & MEM_READ)
                    
                    section_data["flags"] = {
                        "executable": is_exec,
                        "writable": is_write,
                        "readable": is_read,
                        "raw_characteristics": hex(characteristics)
                    }
                    section_data["suspicious"] = is_exec and is_write
                    
                except Exception as e:
                    section_data["flags"] = {
                        "error": f"PE flags error: {str(e)}",
                        "raw_characteristics": hex(getattr(section, 'characteristics', 0))
                    }

            # --- MachO Section Flags ---
            elif isinstance(binary, lief.MachO.Binary) and isinstance(section, lief.MachO.Section):
                 try:
                     flags_val = getattr(section, 'flags', 0)
                     # Check specific MachO flags (constants might vary by LIEF version)
                     # Assuming constants like SECTION_FLAGS exist directly under lief.MachO
                     is_exec = bool(flags_val & lief.MachO.SECTION_FLAGS.PURE_INSTRUCTIONS) if hasattr(lief.MachO, 'SECTION_FLAGS') else False
                     section_data["flags"] = {
                         "executable": is_exec, "writable": False, "readable": True,
                         "raw_flags": hex(flags_val)
                     }
                     section_data["suspicious"] = False # W^X less applicable directly
                 except AttributeError as e:
                      section_data["flags"] = {"error": f"Could not read MachO flags ({e})", "raw_flags": hex(getattr(section, 'flags', 0))}

            sections.append(section_data)

        return sections

   