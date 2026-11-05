import asyncio
import re
from typing import Dict, Any, List

from app.data_store import find_malware_indicator


class EnterpriseSecurityAggregator:
    @staticmethod
    async def query_malware_hash(file_hash: str) -> Dict[str, Any]:
        if not re.fullmatch(r"[a-fA-F0-9]{64}", file_hash):
            raise ValueError("Expected a 64-character SHA-256 hash.")
        indicator = await asyncio.to_thread(find_malware_indicator, file_hash)
        if indicator is None:
            return {
                "hash": file_hash.lower(),
                "threat_intel": "Unknown",
                "source": "No matching local indicator; this is not a clean verdict.",
            }
        return {
            "hash": indicator["sha256"],
            "threat_intel": "Malicious",
            "family": indicator["family"] or "Unknown",
            "source": indicator["source"],
        }

    @staticmethod
    def get_mitre_tactics(attack_type: str) -> Dict[str, str]:
        mapping = {
            "SSH_BRUTE_FORCE": {"tactic": "TA0006 - Credential Access", "technique": "T1110 - Brute Force"},
            "SQL_INJECTION": {"tactic": "TA0001 - Initial Access", "technique": "T1190 - Exploit Public-Facing Application"},
            "DDOS_SYN_FLOOD": {"tactic": "TA0040 - Impact", "technique": "T1498 - Network Denial of Service"},
            "MALWARE_UPLOAD": {"tactic": "TA0002 - Execution", "technique": "T1204 - User Execution"}
        }
        return mapping.get(attack_type, {"tactic": "TA0005 - Defense Evasion", "technique": "T1070 - Indicator Removal"})
