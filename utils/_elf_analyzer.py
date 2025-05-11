import lief
from typing import Dict, List, Union
import binascii

class ELFAnalyzer:
    @staticmethod
    def _analyze_elf(binary: lief.ELF.Binary) -> Dict:
        """ELF-specific analysis with version-safe note processing"""
        result = {
            "dynamic_entries": ELFAnalyzer._get_dynamic_entries(binary),
            "segments": ELFAnalyzer._get_segments(binary),
            "notes": ELFAnalyzer._get_notes(binary),
            "symbol_versions": {
                "present": getattr(binary, 'has_symbol_versioning', False),
                "details": "Parsing skipped"  # Simplified for compatibility
            }
        }
        return result

    @staticmethod
    def _get_dynamic_entries(binary: lief.ELF.Binary) -> List[Dict]:
        """Safely extract dynamic entries"""
        entries = []
        if not hasattr(binary, 'dynamic_entries'):
            return entries

        for entry in binary.dynamic_entries:
            entry_data = {
                "tag": str(getattr(entry, 'tag', 'UNKNOWN')),
                "value": hex(getattr(entry, 'value', 0))
            }
            if name := getattr(entry, 'name', None):
                entry_data["name"] = name
            if hasattr(entry, 'library') and (lib := getattr(entry, 'library', None)):
                entry_data["library"] = getattr(lib, 'name', 'UNKNOWN')
            entries.append(entry_data)
        return entries

    @staticmethod
    def _get_segments(binary: lief.ELF.Binary) -> List[Dict]:
        """Safely extract segment information"""
        segments = []
        if not hasattr(binary, 'segments'):
            return segments

        for segment in binary.segments:
            segments.append({
                "type": ELFAnalyzer._get_segment_type(segment),
                "flags": ELFAnalyzer._get_segment_flags(segment),
                "virtual_address": hex(getattr(segment, 'virtual_address', 0)),
                "virtual_size": hex(getattr(segment, 'virtual_size', 0)),
                "file_offset": hex(getattr(segment, 'file_offset', 0)),
                "physical_size": hex(getattr(segment, 'physical_size', 0))
            })
        return segments

    @staticmethod
    def _get_notes(binary: lief.ELF.Binary) -> List[Dict]:
        """Version-safe note processing"""
        notes = []
        if not getattr(binary, 'has_notes', False):
            return notes

        for note in getattr(binary, 'notes', []):
            try:
                note_data = {
                    "name": getattr(note, 'name', 'Unknown'),
                    "type": ELFAnalyzer._get_note_type(note),
                    "description": ELFAnalyzer._get_note_description(note)
                }
                notes.append(note_data)
            except Exception as e:
                notes.append({"error": f"Failed to process note: {str(e)}"})
        return notes

    @staticmethod
    def _get_segment_type(segment: lief.ELF.Segment) -> str:
        """Handle segment type across LIEF versions"""
        if hasattr(segment, 'type'):
            try:
                return str(segment.type)
            except:
                pass
        return "UNKNOWN"

    @staticmethod
    def _get_segment_flags(segment: lief.ELF.Segment) -> str:
        """Handle segment flags across LIEF versions"""
        if hasattr(segment, 'flags'):
            try:
                return str(segment.flags)
            except:
                pass
        return "UNKNOWN"

    @staticmethod
    def _get_note_type(note: lief.ELF.Note) -> str:
        """Version-safe note type extraction"""
        try:
            if hasattr(note, 'type'):
                # Handle core notes differently if available
                if hasattr(lief.ELF, 'NOTE_TYPES_CORE'):
                    if isinstance(note.type, lief.ELF.NOTE_TYPES_CORE):
                        return f"CORE.{note.type}"
                return str(note.type)
        except:
            pass
        return "UNKNOWN"

    @staticmethod
    def _get_note_description(note: lief.ELF.Note) -> Union[str, Dict]:
        """Safely process note description"""
        try:
            desc = bytes(getattr(note, 'description', b''))
            # Special handling for build IDs
            if ELFAnalyzer._is_build_id(note):
                return {"hex": desc.hex(), "type": "GNU_BUILD_ID"}
            # Try UTF-8 decoding for other notes
            try:
                return desc.decode('utf-8', errors='replace')
            except UnicodeDecodeError:
                return {"hex": desc.hex()}
        except:
            return "ERROR"

    @staticmethod
    def _is_build_id(note: lief.ELF.Note) -> bool:
        """Check if note is GNU Build ID"""
        try:
            if hasattr(lief.ELF, 'NOTE_TYPES'):
                return note.type == lief.ELF.NOTE_TYPES.GNU.BUILD_ID
            return getattr(note, 'name', '') == 'GNU' and 'BUILD_ID' in str(note.type)
        except:
            return False