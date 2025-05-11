import lief
from typing import Dict, List

class ExportAnalyzer:
    
    @staticmethod
    def _get_exports(binary: lief.Binary) -> List[Dict]:
        """Extract exported functions (Handles PE/ELF/MachO)"""
        # (Code from previous correct version - generally robust)
        # ... [Keep the _get_exports code from the previous response] ...
        exports = []
        if not binary:
            return exports

        # Use generic 'exported_functions' if available and not empty
        if hasattr(binary, 'exported_functions') and binary.exported_functions:
            for exp in binary.exported_functions:
                exports.append({
                    "name": getattr(exp, 'name', f"Ordinal_{getattr(exp, 'ordinal', 0)}") if not getattr(exp, 'name', None) else getattr(exp, 'name'),
                    "address": hex(getattr(exp, 'address', 0)),
                    "ordinal": getattr(exp, 'ordinal', None)
                })
        # Fallback for ELF if exported_functions is empty but has dynamic symbols
        elif isinstance(binary, lief.ELF.Binary) and hasattr(binary, 'dynamic_symbols'):
             for sym in binary.dynamic_symbols:
                  # Check if symbol is exported (binding is GLOBAL or WEAK, and not UNDEFINED section)
                  is_exported = (getattr(sym, 'binding', lief.ELF.SYMBOL_BINDINGS.LOCAL) != lief.ELF.SYMBOL_BINDINGS.LOCAL and
                                 getattr(sym, 'shndx', lief.ELF.SYMBOL_SECTION_INDEX.UNDEF) != lief.ELF.SYMBOL_SECTION_INDEX.UNDEF)
                  if is_exported:
                      exports.append({
                         "name": getattr(sym, 'name', 'Unnamed'),
                         "address": hex(getattr(sym, 'value', 0)),
                         "ordinal": None
                      })
        # Fallback for MachO
        elif isinstance(binary, lief.MachO.Binary) and hasattr(binary, 'symbols'):
             for symbol in binary.symbols:
                  # Check if symbol is external and defined
                  is_external = hasattr(symbol, 'is_external') and symbol.is_external
                  is_undefined = hasattr(symbol, 'is_undefined') and symbol.is_undefined
                  if is_external and not is_undefined:
                       exports.append({
                           "name": getattr(symbol, 'name', 'Unnamed'),
                           "address": hex(getattr(symbol, 'value', 0)),
                           "ordinal": None
                       })
        return exports

