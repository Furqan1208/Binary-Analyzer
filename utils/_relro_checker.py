import lief
from typing import Optional
import sys

class RelroChecker:
    @staticmethod
    def _check_relro(binary: lief.Binary) -> Optional[str]:
        """Check ELF RELRO protection level for LIEF 0.16.5"""
        if not isinstance(binary, lief.ELF.Binary):
            return None

        has_relro_segment = False
        has_bind_now_flag = False

        try:
            # Check for GNU_RELRO segment
            if hasattr(binary, 'segments'):
                for segment in binary.segments:
                    # In LIEF 0.16.5, segment type is an integer value
                    # GNU_RELRO is typically 0x6474e552 (decimal 1685382482)
                    if getattr(segment, 'type', 0) == 0x6474e552:
                        has_relro_segment = True
                        break

            # Check BIND_NOW flags using raw values
            if hasattr(binary, 'dynamic_entries'):
                for entry in binary.dynamic_entries:
                    # DT_FLAGS = 0x6, DF_BIND_NOW = 0x8
                    if getattr(entry, 'tag', 0) == 0x6:
                        if getattr(entry, 'value', 0) & 0x8:
                            has_bind_now_flag = True
                    
                    # DT_FLAGS_1 = 0x6ffffffb, DF_1_NOW = 0x1
                    if getattr(entry, 'tag', 0) == 0x6ffffffb:
                        if getattr(entry, 'value', 0) & 0x1:
                            has_bind_now_flag = True

        except Exception as e:
            print(f"Warning: Error during RELRO check: {e}", file=sys.stderr)
            return "Unknown"

        # Determine RELRO level
        if has_relro_segment and has_bind_now_flag:
            return "Full"
        if has_relro_segment:
            return "Partial"
        return "None"