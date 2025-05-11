import lief
from typing import Dict, List

from ._pe_analyzer import PEAnalyzer


class AnomalyFinder:
    @staticmethod
    def _find_anomalies(binary: lief.Binary, sections: List[Dict], imports: List[Dict], security_checks: Dict) -> List[str]:
        """Detect suspicious patterns based on collected data (pass pre-computed data)"""
        anomalies = []

        # 1. High entropy sections
        for section in sections:
            if section.get("entropy", 0.0) > 7.5:
                anomalies.append(f"High entropy ({section['entropy']:.2f}) in section '{section.get('name', 'Unnamed')}'")

        # 2. W^X violations
        for section in sections:
            if section.get("suspicious", False):
                anomalies.append(f"Writable and Executable (W^X) section detected: '{section.get('name', 'Unnamed')}'")

        # 3. Suspicious imports
        suspicious_import_names = {
            # Process Injection / Memory Manipulation
            "createremotethread", "writeprocessmemory", "virtualallocex", "virtualprotectex",
            "resumethread", "setthreadcontext", "ntcreatethreadex", "queueuserapc",
            "mapviewoffile", "unmapviewoffile", "ntmapviewofsection", "zwmapviewofsection",
            # Hooking
            "setwindowshookexa", "setwindowshookexw", "unhookwindowshookex",
            "setwindowlonga", "setwindowlongw", "setwindowlongptra", "setwindowlongptrw", # For GWL_WNDPROC
            # Privilege Escalation / Token Manipulation
            "adjusttokenprivileges", "openprocesstoken", "lookup_privilege_value", # Correct function name
            # Keylogging / Monitoring
            "getasynckeystate", "getkeystate", "setwindowsclipboard", # Potential clipboard stealing
            # Networking
            "socket", "connect", "bind", "listen", "accept", "send", "recv",
            "internetopena", "internetopenw", "internetconnecta", "internetconnectw",
            "httpopenrequesta", "httpopenrequestw", "httpsendrequesta", "httpsendrequestw",
            "internetreadfile", "urlmon", # Often used with URLDownloadToFile
            # Evasion / Anti-Analysis (already partly covered in anti-debug)
            "isdebuggerpresent", "checkremotedebuggerpresent", "sleep", # Long sleeps can be evasive
            "outputdebugstringa", "outputdebugstringw",
            # File System / Registry Manipulation (less specific but common)
            "createfilea", "createfilew", "writefile", "deletefilea", "deletefilew",
            "regcreatekeyexa", "regcreatekeyexw", "regsetvalueexa", "regsetvalueexw",
            # Cryptography (can be legitimate, but common in ransomware/C2)
            "cryptacquirecontext", "cryptimportkey", "cryptencrypt", "cryptdecrypt", "cryptgenkey",
            # Shell Execution
            "shellexecutea", "shellexecutew", "createprocessa", "createprocessw", "winexec"
        }
        import_names_lower = {imp.get("name", "").lower() for imp in imports if imp.get("name")}
        for susp_name in suspicious_import_names:
             if susp_name in import_names_lower:
                  anomalies.append(f"Suspicious import detected: {susp_name}")

        # 4. Entry Point Check
        entry_point = getattr(binary, 'entrypoint', 0)
        if entry_point > 0:
            section_at_ep_info = None
            for s_info in sections:
                 start = int(s_info['virtual_address'], 16)
                 size = s_info['size']
                 if start <= entry_point < start + size:
                     section_at_ep_info = s_info
                     break

            standard_code_sections = {'.text', 'code', 'init', 'fini'} # Common code section names
            if not section_at_ep_info:
                 anomalies.append(f"Entry point ({hex(entry_point)}) is outside of Any known section (Overlay?)")
            else:
                 ep_section_name = section_at_ep_info.get('name', '').lower()
                 ep_section_flags = section_at_ep_info.get('flags', {})
                 is_executable = ep_section_flags.get('executable', False)
                 # Check if name is unusual AND section is not marked executable
                 if ep_section_name not in standard_code_sections and not is_executable :
                      anomalies.append(f"Entry point ({hex(entry_point)}) is in an unusual or non-executable section: '{section_at_ep_info.get('name', 'Unnamed')}'")

        # 5. PE Specific: TLS Callbacks
        if isinstance(binary, lief.PE.Binary):
             pe_specifics = PEAnalyzer._analyze_pe(binary) # Re-analyze PE specifics if needed, or pass down
             tls_info = pe_specifics.get('tls')
             if tls_info and tls_info.get('callbacks'):
                 anomalies.append(f"TLS callbacks detected ({len(tls_info['callbacks'])}), often used for anti-debug/early code execution.")

             # 6. PE Specific: Suspicious Resource Entropy (Use pre-computed section data)
             for section in sections:
                 if '.rsrc' in section.get('name','').lower() or 'resource' in section.get('name','').lower():
                     if section.get('entropy', 0.0) > 7.0:
                          anomalies.append(f"High entropy resource section ('{section.get('name')}') might indicate embedded payload.")

        # 7. Packer Detection Result
        packer = security_checks.get('packer')
        if packer:
             anomalies.append(f"Packer detected: {packer}")

        # 8. Missing Security Features
        if isinstance(binary, lief.PE.Binary) and not security_checks.get("nx_bit", False):
            anomalies.append("NX (Data Execution Prevention) appears to be disabled.")
        if isinstance(binary, lief.ELF.Binary):
             relro_level = security_checks.get("relro", "None")
             if relro_level == "None": anomalies.append("RELRO (Relocation Read-Only) protection is missing.")
             elif relro_level == "Partial": anomalies.append("Partial RELRO detected (Full RELRO provides better protection).")

        return list(Dict.fromkeys(anomalies))

