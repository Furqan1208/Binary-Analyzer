import lief
from typing import Dict, List, Optional

from ._import_analyzer import ImportAnalyzer



class AntiDebugChecker:    
    @staticmethod
    def _check_anti_debug(binary: lief.Binary, imports: Optional[List[Dict]] = None) -> Dict:
        """Enhanced anti-debug detection via imports (PE focus, pass pre-computed imports)"""
        # Use passed imports if available
        if imports is None:
            imports = ImportAnalyzer._get_imports(binary)

        # (Rest of the logic from previous correct version is fine)
        # ... [Keep the rest of the _check_anti_debug code from the previous response] ...
        debug_apis = { # Keep lowercase List
            "isdebuggerpresent": False, "checkremotedebuggerpresent": False,
            "outputdebugstringa": False, "outputdebugstringw": False,
            "ntsetinformationthread": False, "debugactiveprocess": False,
            "debugbreak": False, "int3": False,
            "createtoolhelp32snapshot": False,
            "process32firstw": False, "process32nextw": False,
            "process32first": False, "process32next": False,
            "enumprocesses": False,
            "gettickcount": False, "gettickcount64": False,
            "queryperformancecounter": False, "setunhandledexceptionfilter": False,
            "ntqueryinformationprocess": False, "zwqueryinformationprocess": False,
            "zwsetinformationthread": False, "getthreadcontext": False,
            "setthreadcontext": False, "closehandle": False,
            "findwindowa": False, "findwindoww": False,
            "findwindowexa": False, "findwindowexw": False,
            "blockinput": False, "rdtsc": False, "cpuid": False,
        }
        suspicious_dlls = {"ntdll.dll", "kernel32.dll", "user32.dll", "winmm.dll", "psapi.dll"}

        detected_apis = {}
        suspicious_ordinal_count = 0

        # Iterate pre-computed imports
        for imp in imports:
            dll_name = imp.get("library", "").lower()
            if dll_name not in suspicious_dlls:
                continue

            api_name = imp.get("name", "").lower()
            if not api_name: continue

            # Check by Name
            if not api_name.startswith("ordinal_") and api_name in debug_apis:
                debug_apis[api_name] = True
                detected_apis[f"{dll_name}:{api_name}"] = True
            # Check by Ordinal (already formatted as Ordinal_XXX in _get_imports)
            elif api_name.startswith("ordinal_"):
                ordinal_key = api_name # Use the formatted name
                debug_apis[ordinal_key] = True # Add dynamically if needed
                detected_apis[f"{dll_name}:#{ordinal_key.split('_')[-1]}"] = True # Use # format for output
                suspicious_ordinal_count += 1

        # Calculate score
        score = sum(1 for api, found in debug_apis.items() if found and not api.startswith("ordinal_"))
        score += suspicious_ordinal_count

        return {
            "detected_checks": detected_apis,
            "suspicious_ordinal_imports_count": suspicious_ordinal_count,
            "score": score
        }

