# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
"""Sigma rule backend for the GenericRules class.

This module provides :class:`SigmaRuleBackend`, which handles parsing,
topology injection, and validation for Sigma detection rules.

Reference: https://sigmahq.io/sigma-specification/
"""

import copy
import logging
from typing import Any, Dict, List, Mapping, Tuple

from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

from ..rules import RuleBackend
from ..types import SigmaRuleFormat

logger = logging.getLogger(__name__)


class SigmaRuleBackend(RuleBackend[SigmaRuleFormat]):
    """Backend for Sigma detection rules.

    Handles:
    * Parsing Sigma YAML (one rule per file/dict).
    * Injecting Juju topology as rule tags.
    * Structural validation using PySigma.
    """

    @property
    def file_suffixes(self) -> List[str]:
        return [".yml", ".yaml"]

    def from_dict(
        self,
        rule_dict: Mapping[str, Any],
        **kwargs: Any,
    ) -> List[SigmaRuleFormat]:
        """Parse a Sigma rule dict and inject topology as tags."""
        if not rule_dict:
            raise ValueError("Empty")

        rule_copy: Dict[str, Any] = copy.deepcopy(dict(rule_dict))

        missing = [f for f in ("title", "logsource", "detection") if f not in rule_copy]
        if missing:
            raise ValueError(
                f"Invalid Sigma rule: missing required field(s): {', '.join(missing)}"
            )

        # --- Inject topology as tags ---
        if self.topology:
            tags: List[str] = list(rule_copy.get("tags", []))
            for key, value in self.topology.label_matcher_dict.items():
                tag = f"{key}={value}"
                if tag not in tags:
                    tags.append(tag)
            rule_copy["tags"] = tags

        return [SigmaRuleFormat(**rule_copy)]

    def validate(self, rules: Dict[str, List[SigmaRuleFormat]]) -> Tuple[bool, str]:
        """Validate Sigma rules using pySigma.

        Each rule is parsed through :class:`sigma.rule.SigmaRule` which
        performs full structural and semantic validation.
        """
        errors: List[str] = []
        for idx, rule in enumerate(rules.get("rules", [])):
            label = rule.get("title", f"rule #{idx}")
            try:
                parsed = SigmaRule.from_dict(dict(rule), collect_errors=True)
                for err in parsed.errors:
                    errors.append(f"Sigma rule '{label}': {err}")
            except SigmaError as e:
                errors.append(f"Sigma rule '{label}': {e}")
        if errors:
            return False, "; ".join(errors)
        return True, ""

    def as_dict(self, items: List[SigmaRuleFormat]) -> Dict[str, List[SigmaRuleFormat]]:
        """Serialise as ``{"rules": [...]}``."""
        return {"rules": items} if items else {}
