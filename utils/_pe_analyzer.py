import lief
from typing import Dict, List
 

class PEAnalyzer:
    @staticmethod
    def _analyze_pe(binary: lief.PE.Binary) -> Dict:
        """PE-specific analysis"""
        # (Code from previous correct version - generally robust, add getattr)
        # ... [Keep most of the _analyze_pe code, add getattr checks] ...
        result = {}

        # Optional Header Info
        if hasattr(binary, 'optional_header'):
             opt_header = binary.optional_header
             # Use getattr for safe access to optional header fields
             result["optional_header"] = {
                 "subsystem": str(getattr(opt_header, 'subsystem', 'UNKNOWN')),
                 "dll_characteristics": [str(flag) for flag in getattr(opt_header, 'dll_characteristics_list', [])],
                 "major_linker_version": getattr(opt_header, 'major_linker_version', 0),
                 "minor_linker_version": getattr(opt_header, 'minor_linker_version', 0),
                 "sizeof_code": getattr(opt_header, 'sizeof_code', 0),
                 "sizeof_initialized_data": getattr(opt_header, 'sizeof_initialized_data', 0),
                 "sizeof_uninitialized_data": getattr(opt_header, 'sizeof_uninitialized_data', 0),
             }

        # Rich header
        if getattr(binary, 'has_rich_header', False):
            try:
                rich_header = getattr(binary, 'rich_header', None)
                if rich_header:
                    rich_entries = []
                    for entry in getattr(rich_header, 'entries', []):
                         rich_entries.append({
                              "id": getattr(entry, 'id', 0),
                              "build_id": getattr(entry, 'build_id', 0),
                              "count": getattr(entry, 'count', 0)
                         })
                    result["rich_header"] = {
                        "key": hex(getattr(rich_header, 'key', 0)),
                        "entries": rich_entries
                    }
                else: result["rich_header"] = {"error": "Rich Header object not found"}
            except Exception as e: result["rich_header"] = {"error": f"Failed to parse Rich Header: {e}"}


        # Resources
        if hasattr(binary, 'has_resources') and binary.has_resources:
            result["resources"] = []
            try:
                resources = getattr(binary, 'resources', [])
                if isinstance(resources, lief.PE.ResourceDirectory):
                    # Handle the case where 'resources' might be a single directory
                    resources_to_process = [resources]
                else:
                    resources_to_process = resources

                for resource in resources_to_process:
                    is_dir = isinstance(resource, lief.PE.ResourceDirectory)
                    is_data = isinstance(resource, lief.PE.ResourceData)
                    res_info = {
                        "id": getattr(resource, 'id', 0),
                        "name": getattr(resource, 'name', None),
                        "type": None,
                        "language": None,
                        "sublanguage": None,
                        "size": 0,
                        "offset": 0,
                        "is_directory": is_dir,
                        "is_data": is_data
                    }
                    if is_dir and hasattr(resource, 'type'):
                        res_info["type"] = str(resource.type)
                    if is_data:
                        if hasattr(resource, 'language'):
                            try:
                                res_info["language"] = str(lief.PE.RESOURCE_LANGUAGES(resource.language))
                            except ValueError:
                                res_info["language"] = f"Unknown ({resource.language})"
                        if hasattr(resource, 'sublanguage'):
                            try:
                                res_info["sublanguage"] = str(lief.PE.RESOURCE_SUBLANGUAGES(resource.sublanguage))
                            except ValueError:
                                res_info["sublanguage"] = f"Unknown ({resource.sublanguage})"
                        res_info["size"] = getattr(resource, 'size', 0)
                        res_info["offset"] = getattr(resource, 'offset', 0)
                    result["resources"].append(res_info)
            except Exception as e:
                result["resources"] = {"error": f"Failed to parse resources: {e}"}
        elif hasattr(binary, 'has_resources') and not binary.has_resources:
            result["resources"] = []
        else:
            result["resources"] = None
        # TLS (Thread Local Storage) Data
        if getattr(binary, 'has_tls', False):
             tls = getattr(binary, 'tls', None)
             if tls:
                 callbacks = getattr(tls, 'callbacks', [])
                 addr_rawdata = getattr(tls, 'addressof_rawdata', (None,)) # Expect tuple
                 addr_index = getattr(tls, 'addressof_index', None)
                 result["tls"] = {
                     "callbacks": [hex(cb) for cb in callbacks],
                     "directory_address": hex(addr_rawdata[0]) if addr_rawdata[0] is not None else None,
                     "index_address": hex(addr_index) if addr_index is not None else None,
                 }

        return result

 