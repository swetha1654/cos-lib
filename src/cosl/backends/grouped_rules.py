# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
"""Shared base for groups-based rule backends (Prometheus & Loki).

This module provides :class:`_GroupedRuleBackend`, the common base class for
:class:`~cosl.prometheus.PrometheusRuleBackend` and
:class:`~cosl.loki.LokiRuleBackend`.
"""

import copy
import hashlib
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple, cast

import yaml

from ..cos_tool import CosTool
from ..juju_topology import JujuTopology
from ..rules import RuleBackend
from ..types import (
    RULE_TYPES,
    OfficialRuleFileFormat,
    OfficialRuleFileItem,
    QueryType,
    SingleRuleFormat,
)

logger = logging.getLogger(__name__)


class _GroupedRuleBackend(RuleBackend[OfficialRuleFileItem]): # type: ignore
    """Shared base for Prometheus and Loki rule backends.

    Handles the groups-based rule format, topology injection into group names,
    rule labels, and expressions.  Subclasses only need to set :attr:`query_type`.
    """

    query_type: QueryType

    def __init__(self, topology: Optional[JujuTopology] = None) -> None:
        self.topology = topology
        self.tool = CosTool(default_query_type=self.query_type)

    @property
    def file_suffixes(self) -> List[str]:
        return [".rule", ".rules", ".yml", ".yaml"]

    def from_dict(
        self,
        rule_dict: Mapping[str, Any],
        **kwargs: Any,
    ) -> List[OfficialRuleFileItem]:
        """Parse a Prometheus/Loki rule dict, normalise, and inject topology.

        Args:
            rule_dict: Raw rule content as a YAML-loaded dict.
            **kwargs: Accepts ``group_name`` (str) — an identifier for the
                group (typically the file stem), and ``group_name_prefix``
                (str) — a prefix for the group name (typically topology
                identifier + relative path).
        """
        group_name: Optional[str] = kwargs.get("group_name")
        group_name_prefix: Optional[str] = kwargs.get("group_name_prefix")

        if not rule_dict:
            raise ValueError("Empty")

        rule_copy = copy.deepcopy(rule_dict)
        if self._is_official_format(rule_copy):
            groups = [OfficialRuleFileItem(**g) for g in rule_copy.get("groups", [])]
        elif self._is_single_rule_format(rule_copy):
            single_rule = cast(SingleRuleFormat, rule_copy)
            if not group_name:
                # Note: the caller of this function should ensure this never happens:
                # Either we use the standard format, or we'd pass a group_name.
                # If/when we drop support for the single-rule-per-file format, this won't
                # be needed anymore.
                group_name = hashlib.shake_256(str(single_rule).encode("utf-8")).hexdigest(10)

            # convert to list of groups to match official rule format
            groups = [OfficialRuleFileItem(name=group_name, rules=[single_rule])]
        else:
            # invalid/unsupported
            raise ValueError("Invalid rule format")

        # update rules with additional metadata
        for group in groups:
            if not self._is_already_modified(group["name"]):
                # update group name with topology and sub-path
                new_name = "_".join(filter(None, [group_name_prefix, group["name"]]))
                if not new_name.endswith("_rules"):
                    new_name += "_rules"
                group["name"] = new_name
            # after sanitizing we should not modify group.name anymore
            group["name"] = self._sanitize_metric_name(group["name"])

            # add "juju_" topology labels
            for rule in group["rules"]:
                if "labels" not in rule:
                    rule["labels"] = {}

                if self.topology:
                    # only insert labels that do not already exist
                    for label, val in self.topology.label_matcher_dict.items():
                        if label not in rule["labels"]:
                            rule["labels"][label] = val

                    # Inject topology matchers into the expression
                    repl = r'job=~".+"' if self.query_type == "logql" else ""
                    rule["expr"] = self.tool.inject_label_matchers(
                        expression=re.sub(r"%%juju_topology%%,?", repl, rule["expr"]),
                        topology={
                            k: rule["labels"][k]
                            for k in ("juju_model", "juju_model_uuid", "juju_application")
                            if rule["labels"].get(k) is not None
                        },
                        query_type=self.query_type,
                    )

        return groups

    def from_file(
        self,
        file_path: Path,
        **kwargs: Any,
    ) -> List[OfficialRuleFileItem]:
        """Read a rule file, using file context for group naming.

        Args:
            file_path: Absolute path to the rule file.
            **kwargs: Must include ``root_path`` (:class:`~pathlib.Path`) —
                the root rules directory used for computing relative paths
                for group name prefixes.
        """
        root_path: Path = kwargs.get("root_path", file_path.parent)
        with file_path.open() as f:
            try:
                rule_file = yaml.safe_load(f)
            except Exception as e:
                logger.error("Failed to read rules from %s: %s", file_path.name, e)
                return []

        # Compute group name context from topology + relative path
        rel_path = file_path.parent.relative_to(root_path)
        rel_path_str = "" if rel_path == Path(".") else str(rel_path)
        prefix_parts = [self.topology.identifier] if self.topology else []
        prefix_parts.append(rel_path_str)
        group_name_prefix = "_".join(filter(None, prefix_parts))

        try:
            return self.from_dict(
                rule_file,
                group_name=file_path.stem,
                group_name_prefix=group_name_prefix,
            )
        except ValueError as e:
            logger.error("Invalid rules file: %s (%s)", file_path.name, e)
            return []

    def validate(self, rules: Dict[str, List[OfficialRuleFileItem]]) -> Tuple[bool, str]:
        """Validate rules using ``cos-tool``."""
        return self.tool.validate_alert_rules(OfficialRuleFileFormat(**rules))

    def as_dict(self, items: List[OfficialRuleFileItem]) -> Dict[str, List[OfficialRuleFileItem]]:
        """Serialise as ``{"groups": [...]}``."""
        return {"groups": items} if items else {}

    @staticmethod
    def _is_official_format(rules_dict: Mapping[str, Any]) -> bool:
        return "groups" in rules_dict

    @staticmethod
    def _is_single_rule_format(rules_dict: Mapping[str, Any]) -> bool:
        return "expr" in rules_dict and not RULE_TYPES.isdisjoint(rules_dict)

    @staticmethod
    def _is_already_modified(name: str) -> bool:
        """Detect whether a group name already contains a topology UUID hash."""
        return re.match(r"^.*?_[\da-f]{8}_.*?rules$", name) is not None

    @staticmethod
    def _sanitize_metric_name(metric_name: str) -> str:
        """Sanitize a metric name per the Prometheus data model."""
        return "".join(char if re.match(r"[a-zA-Z0-9_:]", char) else "_" for char in metric_name)
