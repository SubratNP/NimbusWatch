"""YAML Rule Catalog Loader and Validator."""

import logging
from pathlib import Path
from typing import List, Dict, Optional
import yaml

from nimbuswatch.config import settings
from nimbuswatch.schemas.rules import (
    MisconfigurationRule,
    AttackPatternRule,
    ToxicCombinationRule,
)

logger = logging.getLogger(__name__)

class RuleCatalog:
    """Loads, validates, and indexes YAML rules."""

    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = rules_dir or settings.RULES_DIR
        self.misconfiguration_rules: Dict[str, MisconfigurationRule] = {}
        self.attack_patterns: Dict[str, AttackPatternRule] = {}
        self.toxic_combinations: Dict[str, ToxicCombinationRule] = {}
        self.reload()

    def reload(self) -> None:
        """Reload all rules from the rules directory."""
        self.misconfiguration_rules.clear()
        self.attack_patterns.clear()
        self.toxic_combinations.clear()

        # Load Misconfiguration Rules
        misconfig_dir = self.rules_dir / "misconfigurations"
        if misconfig_dir.exists():
            for file_path in misconfig_dir.glob("*.yaml"):
                rule = self._load_misconfig_file(file_path)
                if rule:
                    self.misconfiguration_rules[rule.rule_id] = rule

        # Load Attack Patterns
        attack_dir = self.rules_dir / "attack_patterns"
        if attack_dir.exists():
            for file_path in attack_dir.glob("*.yaml"):
                pattern = self._load_attack_pattern_file(file_path)
                if pattern:
                    self.attack_patterns[pattern.attack_id] = pattern

        # Load Toxic Combinations
        toxic_dir = self.rules_dir / "toxic_combinations"
        if toxic_dir.exists():
            for file_path in toxic_dir.glob("*.yaml"):
                combo = self._load_toxic_combination_file(file_path)
                if combo:
                    self.toxic_combinations[combo.combination_id] = combo

        logger.info(
            f"Loaded {len(self.misconfiguration_rules)} misconfiguration rules, "
            f"{len(self.attack_patterns)} attack patterns, and "
            f"{len(self.toxic_combinations)} toxic combinations."
        )

    def _load_misconfig_file(self, path: Path) -> Optional[MisconfigurationRule]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            return MisconfigurationRule(**data)
        except Exception as e:
            logger.error(f"Failed to load misconfiguration rule {path}: {e}")
            return None

    def _load_attack_pattern_file(self, path: Path) -> Optional[AttackPatternRule]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            return AttackPatternRule(**data)
        except Exception as e:
            logger.error(f"Failed to load attack pattern {path}: {e}")
            return None

    def _load_toxic_combination_file(self, path: Path) -> Optional[ToxicCombinationRule]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            return ToxicCombinationRule(**data)
        except Exception as e:
            logger.error(f"Failed to load toxic combination {path}: {e}")
            return None

    def get_misconfiguration_rules(self, service: Optional[str] = None) -> List[MisconfigurationRule]:
        if service:
            return [r for r in self.misconfiguration_rules.values() if r.service.upper() == service.upper()]
        return list(self.misconfiguration_rules.values())

    def get_attack_patterns(self) -> List[AttackPatternRule]:
        return list(self.attack_patterns.values())

    def get_toxic_combinations(self) -> List[ToxicCombinationRule]:
        return list(self.toxic_combinations.values())

# Global catalog singleton
catalog = RuleCatalog()
