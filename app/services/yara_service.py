import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import yara
from app.config import settings

logger = logging.getLogger(__name__)


class YaraService:
    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = Path(rules_dir or settings.yara_rules_path)
        self.rules: Optional[yara.Rules] = None
        self.loaded_files: List[str] = []
        self.load_error: Optional[str] = None
        self.load_rules()

    def load_rules(self) -> bool:
        """Load and compile all .yar and .yara rules from the rules directory."""
        self.loaded_files = []
        self.load_error = None

        if not self.rules_dir.exists():
            self.rules_dir.mkdir(parents=True, exist_ok=True)

        rule_files = {}
        for ext in ("*.yar", "*.yara"):
            for rule_file in self.rules_dir.glob(ext):
                # namespace key must be identifier-friendly
                namespace = rule_file.stem.replace("-", "_").replace(" ", "_")
                rule_files[namespace] = str(rule_file.resolve())

        if not rule_files:
            logger.warning("No YARA rule files found in %s", self.rules_dir)
            self.rules = None
            return False

        try:
            self.rules = yara.compile(filepaths=rule_files)
            self.loaded_files = list(rule_files.values())
            logger.info("Successfully compiled %d YARA rule files", len(rule_files))
            return True
        except yara.SyntaxError as e:
            self.load_error = f"YARA syntax error: {str(e)}"
            logger.error(self.load_error)
            self.rules = None
            return False
        except Exception as e:
            self.load_error = f"Error compiling YARA rules: {str(e)}"
            logger.error(self.load_error)
            self.rules = None
            return False

    def get_status(self) -> Dict[str, Any]:
        """Health check and status of the YARA scanner."""
        available = self.rules is not None
        return {
            "available": available,
            "engine": "YARA",
            "rules_directory": str(self.rules_dir),
            "loaded_files_count": len(self.loaded_files),
            "loaded_files": [Path(f).name for f in self.loaded_files],
            "error": self.load_error
        }

    def reload_rules(self) -> Dict[str, Any]:
        """Dynamically reload rules without server restart."""
        success = self.load_rules()
        status = self.get_status()
        status["reloaded"] = success
        return status

    def scan_file(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Scan file with loaded YARA rules."""
        path = Path(file_path)
        if not path.exists():
            return {
                "status": "ERROR",
                "matched_rules": [],
                "threats": [],
                "engine": "YARA",
                "available": self.rules is not None,
                "error": f"File not found: {file_path}"
            }

        if self.rules is None:
            # Try reloading rules once
            self.load_rules()
            if self.rules is None:
                return {
                    "status": "UNABLE_TO_SCAN",
                    "matched_rules": [],
                    "threats": [],
                    "engine": "YARA",
                    "available": False,
                    "error": f"YARA rules not compiled or available: {self.load_error or 'No rules loaded'}"
                }

        try:
            matches = self.rules.match(str(path))
            return self._format_matches(matches)
        except Exception as e:
            logger.error("YARA scan error on file %s: %s", path, e)
            return {
                "status": "ERROR",
                "matched_rules": [],
                "threats": [],
                "engine": "YARA",
                "available": True,
                "error": str(e)
            }

    def scan_data(self, data: bytes) -> Dict[str, Any]:
        """Scan raw byte buffer with loaded YARA rules."""
        if self.rules is None:
            self.load_rules()
            if self.rules is None:
                return {
                    "status": "UNABLE_TO_SCAN",
                    "matched_rules": [],
                    "threats": [],
                    "engine": "YARA",
                    "available": False,
                    "error": f"YARA rules not compiled: {self.load_error or 'No rules'}"
                }

        try:
            matches = self.rules.match(data=data)
            return self._format_matches(matches)
        except Exception as e:
            logger.error("YARA scan error on bytes: %s", e)
            return {
                "status": "ERROR",
                "matched_rules": [],
                "threats": [],
                "engine": "YARA",
                "available": True,
                "error": str(e)
            }

    def _format_matches(self, matches: List[yara.Match]) -> Dict[str, Any]:
        matched_rules = []
        threats = []
        has_malware = False
        has_suspicious = False

        for match in matches:
            rule_name = match.rule
            meta = match.meta or {}
            description = meta.get("description", f"Matched YARA rule {rule_name}")
            threat_category = meta.get("threat_category", "heuristic")
            severity = meta.get("severity", "MEDIUM").upper()

            matched_rules.append({
                "rule": rule_name,
                "namespace": match.namespace,
                "tags": match.tags,
                "meta": meta
            })

            threats.append({
                "scanner_name": "yara",
                "threat_name": rule_name,
                "threat_category": threat_category,
                "severity": severity,
                "description": description
            })

            if severity in ("CRITICAL", "HIGH") and threat_category == "malware":
                has_malware = True
            else:
                has_suspicious = True

        if has_malware:
            status = "MALICIOUS"
        elif has_suspicious:
            status = "SUSPICIOUS"
        else:
            status = "CLEAN"

        return {
            "status": status,
            "matched_rules": matched_rules,
            "threats": threats,
            "engine": "YARA",
            "available": True,
            "error": None
        }


yara_service = YaraService()

