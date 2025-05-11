import lief
from typing import Dict, List


class ImportAnalyzer:
    @staticmethod
    def _get_imports(binary: lief.Binary) -> List[Dict]:
        """Extract imported functions (Handles PE/ELF/MachO)"""
        # (Code from previous correct version - generally robust)
        # ... [Keep the _get_imports code from the previous response] ...
        imports = []
        if not binary :
             return imports

        # Check for specific import structures first
        # --- PE Imports (including ordinals and delay-load) ---
        if isinstance(binary, lief.PE.Binary):
            pe_imports = []
            if hasattr(binary, 'imports'):
                 pe_imports.extend(binary.imports)
            # Also check delay-loaded imports if the attribute exists
            if hasattr(binary, "delay_imports"):
                 pe_imports.extend(binary.delay_imports)

            for entry in pe_imports:
                lib_name = getattr(entry, 'name', "Unknown")
                is_delayed = hasattr(entry,'attribute') and entry.attribute == lief.PE.DELAY_IMPORT_ATTRIBUTE.DELAYED # Heuristic check
                for func in getattr(entry, 'entries', []):
                    is_name = getattr(func,'is_name',False)
                    ordinal = getattr(func,'ordinal',0)
                    name = getattr(func,'name', None)
                    imports.append({
                        "name": name if is_name else f"Ordinal_{ordinal}",
                        "library": lib_name,
                        "ordinal": ordinal if not is_name else None,
                        "hint": getattr(func, 'hint', None),
                        "is_delayed": is_delayed
                    })

        # --- ELF Imports ---
        elif isinstance(binary, lief.ELF.Binary):
            if hasattr(binary, 'imported_symbols') and binary.imported_symbols:
                 for sym in binary.imported_symbols:
                    lib = getattr(sym, 'library', None)
                    imports.append({
                        "name": getattr(sym, 'name', 'Unnamed'),
                        "library": getattr(lib, 'name', 'Unknown') if lib else "Unknown",
                        "type": str(getattr(sym, 'type', 'UNKNOWN'))
                    })
            elif hasattr(binary, 'imports'): # Fallback via generic imports
                 for imp_entry in binary.imports:
                    imports.append({"name": getattr(imp_entry, 'name', 'Unnamed'), "library": "Unknown", "type":"GenericImport"})

        # --- MachO Imports ---
        elif isinstance(binary, lief.MachO.Binary):
             if hasattr(binary, 'commands') and hasattr(binary, 'symbols'):
                 # Map library ordinals to names first
                 lib_map = {}
                 for command in binary.commands:
                      if hasattr(command, 'command') and command.command == lief.MachO.LOAD_COMMAND_TYPES.LOAD_DYLIB:
                           if hasattr(command, 'dylib'):
                                lib_map[command.ordinal] = getattr(command.dylib, 'name', 'Unknown')

                 # Find symbols imported from these libraries
                 for symbol in binary.symbols:
                      if hasattr(symbol, 'has_binding_info') and symbol.has_binding_info:
                           binding_info = getattr(symbol, 'binding_info', None)
                           if binding_info and getattr(binding_info, 'library_ordinal', 0) in lib_map:
                                imports.append({
                                    "name": getattr(symbol, 'name', 'Unnamed'),
                                    "library": lib_map[binding_info.library_ordinal],
                                    "type": "Function" # Assumption
                                })

        return imports

