import lief
from typing import Dict, Optional



class CertificateChecker:
    @staticmethod
    def _check_certificates(binary: lief.Binary) -> Optional[Dict]:
        """Verify digital signatures (PE specific)"""
        # (Code from previous correct version - generally robust)
        # ... [Keep the _check_certificates code from the previous response] ...
        if not isinstance(binary, lief.PE.Binary):
            return None

        result = {"signed": False, "verified": None, "signers": []}
        try:
            # Use getattr for safe access to signature attributes
            if getattr(binary, 'has_signature', False):
                 result["signed"] = True
                 verification_status_enum = binary.verify_signature(0) # Check flags if needed
                 result["verified"] = str(verification_status_enum) # Store enum string representation

                 signatures = getattr(binary, 'signatures', [])
                 for sig in signatures:
                      signer_info_list = []
                      for signer in getattr(sig, 'signers', []):
                           issuer_str = "Error reading issuer"
                           serial_str = "Error reading serial"
                           try: # Safely access issuer/serial
                               issuer_str = str(signer.issuer)
                               serial_str = signer.serial_number.hex()
                           except Exception: pass

                           signer_info_list.append({
                               "issuer": issuer_str,
                               "serial_number": serial_str,
                               "version": getattr(signer, 'version', None)
                           })
                      result["signers"].append({
                           "algorithm": str(getattr(sig, 'digest_algorithm', 'Unknown')),
                           "signer_details": signer_info_list
                      })
        except AttributeError as e:
             result["error"] = f"Error checking signature (Attribute Missing: {e})"
        except Exception as e:
             result["error"] = f"Error checking signature: {e}"
        return result

 