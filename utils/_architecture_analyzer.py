import lief

class ArchitectureAnalyzer:
    @staticmethod
    def _get_architecture(binary: lief.Binary) -> str:
        """Get normalized architecture name for PE, ELF, and Mach-O"""
        try:
            if isinstance(binary, lief.PE.Binary):
                # PE header attribute is 'machine'
                if not hasattr(binary, 'header') or not hasattr(binary.header, 'machine'):
                     return "UnknownArch (PE Header missing machine attribute)"
                machine_enum = binary.header.machine
                arch_str = str(machine_enum)
                # Check common PE machine types
                if "AMD64" in arch_str: return "x64"
                if "IA64" in arch_str: return "IA64"
                if "I386" in arch_str: return "x86"
                if "ARM64" in arch_str: return "ARM64"
                if "ARM" in arch_str: return "ARM" # Catches ARM, ARMNT
                return arch_str

            elif isinstance(binary, lief.ELF.Binary):
                 # ELF header attribute is 'machine_type'
                 if not hasattr(binary, 'header') or not hasattr(binary.header, 'machine_type'):
                      return "UnknownArch (ELF Header missing machine_type attribute)"
                 machine_enum = binary.header.machine_type
                 arch_str = str(machine_enum)
                 # Check common ELF machine types (adjust strings as needed based on LIEF version)
                 if "x86_64" in arch_str.lower(): return "x64"
                 if "i386" in arch_str.lower(): return "x86"
                 if "aarch64" in arch_str.lower(): return "ARM64"
                 if "arm" in arch_str.lower(): return "ARM"
                 return arch_str

            elif isinstance(binary, lief.MachO.Binary):
                 # MachO header attribute is 'cpu_type'
                 if not hasattr(binary, 'header') or not hasattr(binary.header, 'cpu_type'):
                      return "UnknownArch (MachO Header missing cpu_type attribute)"
                 machine_enum = binary.header.cpu_type
                 cpu_type_str = str(machine_enum)
                 # Check common MachO CPU types
                 if "X86_64" in cpu_type_str: return "x64"
                 if "X86" in cpu_type_str: return "x86"
                 if "ARM64" in cpu_type_str: return "ARM64"
                 if "ARM" in cpu_type_str: return "ARM"
                 return cpu_type_str
            else:
                # Fallback for unknown formats
                return "UnknownFormat"
        except AttributeError as e:
             return f"UnknownArch (AttributeError: {e})"
        except Exception as e:
             return f"UnknownArch (Error: {e})"

