# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
"""The rules module.

## Overview

## Rules class (Legacy)

This library also supports gathering alerting and recording rules from all
related charms and enabling corresponding alerting/recording rules within the
Prometheus charm.  Alert rules are automatically gathered by `AlertRules`
charms when using this library, from a directory conventionally named as one of:
- `prometheus_alert_rules`
- `prometheus_recording_rules`
- `loki_alert_rules`
- `loki_recording_rules`

This directory must reside at the top level in the `src` folder of the consumer
charm. Each file in this directory is assumed to be in one of two formats:
- the official Prometheus rule format, conforming to the
[Prometheus docs](https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/)
- a single rule format, which is a simplified subset of the official format,
comprising a single alert rule per file, using the same YAML fields.

The file name must have one of the following extensions:
- `.rule`
- `.rules`
- `.yml`
- `.yaml`

An example of the contents of such a file in the custom single rule
format is shown below.

```
alert: HighRequestLatency
expr: job:request_latency_seconds:mean5m{my_key=my_value} > 0.5
for: 10m
labels:
  severity: Medium
  type: HighLatency
annotations:
  summary: High request latency for {{ $labels.instance }}.
```

The `[Alert|Recording]Rules` instance will read all available rules and
also inject "filtering labels" into the expressions. The
filtering labels ensure that rules are localised to the metrics
provider charm's Juju topology (application, model and its UUID). Such
a topology filter is essential to ensure that rules submitted by
one provider charm generates information only for that same charm. When
rules are embedded in a charm, and the charm is deployed as a
Juju application, the rules from that application have their
expressions automatically updated to filter for metrics/logs coming from
the units of that application alone. This removes risk of spurious
evaluation, e.g., when you have multiple deployments of the same charm
monitored by the same Prometheus or Loki.

Not all rules one may want to specify can be embedded in a
charm. Some rules will be specific to a user's use case. This is
the case, for example, of rules that are based on business
constraints, like expecting a certain amount of requests to a specific
API every five minutes. Such alerting or recording rules can be specified
via the [COS Config Charm](https://charmhub.io/cos-configuration-k8s),
which allows importing alert rules and other settings like dashboards
from a Git repository.

Gathering rules and generating rule files within a
charm is easily done using the `alerts()` or `recording_rules()` method(s)
of the consuming charm. Rules generated will automatically include Juju
topology labels. These labels indicate the source of the record or alert.
The following labels are automatically included with each rule:

- `juju_model`
- `juju_model_uuid`
- `juju_application`

## AbstractRules (Latest)

The ``AbstractRules`` class is a format-agnostic aggregator that collects alerting,
recording, or detection rules from files, directories and dicts.  All format-specific
logic — parsing, topology injection, validation, and serialization — is
delegated to a :class:`RuleBackend` implementation.

Usage::

    from cosl.juju_topology import JujuTopology
    from cosl.backends.prometheus import PrometheusRuleBackend
    from cosl.backends.loki import LokiRuleBackend
    from cosl.sigma import SigmaRuleBackend

    self._topology = JujuTopology.from_charm(charm)

    # Prometheus
    prom_rules = AbstractRules(backend=PrometheusRuleBackend(topology=self._topology))
    prom_rules.add_path("src/prometheus_alert_rules")
    print(prom_rules.as_dict())   # {"groups": [...]}

    # Loki
    loki_rules = AbstractRules(backend=LokiRuleBackend(topology=self._topology))
    loki_rules.add_path("src/loki_alert_rules")
    print(loki_rules.as_dict())   # {"groups": [...]}

    # Sigma
    sigma_rules = AbstractRules(backend=SigmaRuleBackend(topology=self._topology))
    sigma_rules.add_path("src/sigma_rules")
    print(sigma_rules.as_dict())   # {"rules": [...]}
"""

import contextlib
import copy
import hashlib
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import (
    Any,
    ClassVar,
    Dict,
    Final,
    Generic,
    List,
    Mapping,
    Optional,
    Protocol,
    Tuple,
    TypeVar,
    Union,
    cast,
    runtime_checkable,
)

import yaml

from . import CosTool, JujuTopology
from .types import (
    RULE_TYPES,
    OfficialRuleFileFormat,
    OfficialRuleFileItem,
    QueryType,
    RuleType,
    SingleRuleFormat,
)

logger = logging.getLogger(__name__)

HOST_METRICS_MISSING_RULE_NAME = "HostMetricsMissing"

_generic_alert_rules: Final = SimpleNamespace(
    # We use "5m" to avoid false positives on expected temporary "down", e.g. during intentional (re)start.
    # Juju topology will be later injected by providers of alert rules.
    host_down={
        "alert": "HostDown",
        "expr": "up < 1",
        "for": "5m",
        "labels": {"severity": "critical"},
        "annotations": {
            "summary": "Host '{{ $labels.instance }}' is down.",
            "description": "Juju application '{{ $labels.juju_application }}' in model '{{ $labels.juju_model }}' is down. Prometheus has been unable to scrape it during at least the past five minutes.",
        },
    },
    host_metrics_missing={
        "alert": HOST_METRICS_MISSING_RULE_NAME,
        "expr": "absent(up)",
        "for": "5m",
        "labels": {
            "severity": "warning"
        },  # The remote writer will set this to critical for machine charms when initializing PrometheusRemoteWriteConsumer.
        "annotations": {
            "summary": "Unit '{{ $labels.juju_unit }}' of application '{{ $labels.juju_application }}' is down or failing to remote write.",
            "description": "`Up` missing for unit '{{ $labels.juju_unit }}' of application {{ $labels.juju_application }} in model {{ $labels.juju_model }}. Please ensure the unit or the collector scraping it is up and is able to successfully reach the metrics backend.",
        },
    },
    aggregator_metrics_missing={
        "alert": "AggregatorMetricsMissing",
        "expr": "absent(up)",
        "for": "5m",
        "labels": {"severity": "critical"},
        "annotations": {
            "summary": "Metrics not received from application '{{ $labels.juju_application }}'. All units are down or failing to remote write.",
            "description": "`Up` missing for ALL units of application {{ $labels.juju_application }} in model {{ $labels.juju_model }}. This can also mean the units or the collector scraping them are unable to reach the remote write endpoint of the metrics backend. Please ensure the correct firewall rules are applied.",
        },
    },
)

"""
Generic alert rules are in groups to ensure a predictable group name.
"""


class _GenericAlertGroups:
    _application_rules: ClassVar[OfficialRuleFileFormat] = {
        "groups": [
            {
                "name": "HostHealth",
                "rules": [
                    _generic_alert_rules.host_down,
                    _generic_alert_rules.host_metrics_missing,
                ],
            },
        ]
    }
    _aggregator_rules: ClassVar[OfficialRuleFileFormat] = {
        "groups": [
            {
                "name": "AggregatorHostHealth",
                "rules": [
                    _generic_alert_rules.host_metrics_missing,
                    _generic_alert_rules.aggregator_metrics_missing,
                ],
            },
        ]
    }

    @property
    def application_rules(self) -> OfficialRuleFileFormat:
        # Group names must be unique per alert rule file. The final group names may be adjusted by
        # the providers of alert rules to include some topology information, to address deduplication.
        return copy.deepcopy(self._application_rules)

    @property
    def aggregator_rules(self) -> OfficialRuleFileFormat:
        # If we push to Prometheus via remote-write with an aggregator, there are no UP metrics
        # associated. Only a time series for the metrics we have pushed is available so omit the
        # HostDown rule.
        return copy.deepcopy(self._aggregator_rules)


generic_alert_groups: Final = _GenericAlertGroups()

T = TypeVar("T")


class InvalidRulePathError(Exception):
    """Raised if the rules folder cannot be found or is otherwise invalid."""

    def __init__(
        self,
        rules_absolute_path: Path,
        message: str,
    ):
        self.rules_absolute_path = rules_absolute_path
        self.message = message

        super().__init__(self.message)


@dataclass
class Result(Generic[T]):
    """Result of rule validation.

    Attributes:
        rules: The rules dictionary.
        errmsg: Optional error message produced during validation.
    """

    rules: Dict[str, List[T]]
    errmsg: Optional[str]


@runtime_checkable
class RuleBackend(Protocol[T]):
    """Protocol for format-specific rule handling.

    Type parameter *T* is the internal representation of a single rule item.

    Implementations must provide:

    * :attr:`file_suffixes` — which file extensions this backend reads.
    * :meth:`from_dict` — parse a raw dict into normalised rule items,
      injecting Juju topology where appropriate.
    * :meth:`from_file` — read a rule file and parse it.
    * :meth:`validate` — check the serialised output for correctness.
    * :meth:`as_dict` — convert internal rule items into the backend's output format.
    """

    @property
    def file_suffixes(self) -> List[str]:
        """File extensions this backend supports (e.g. ``['.rule', '.yml']``)."""
        ...

    def from_dict(
        self,
        rule_dict: Mapping[str, Any],
        **kwargs: Any,
    ) -> List[T]:
        """Parse a rule dict, normalise it, and inject topology.

        Args:
            rule_dict: Raw rule content as a YAML-loaded dict.
            **kwargs: Backend-specific keyword arguments.

        Returns:
            A list of normalised rule items.

        Raises:
            ValueError: If *rule_dict* is empty or in an invalid format.
        """
        ...

    def from_file(
        self,
        file_path: Path,
        **kwargs: Any,
    ) -> List[T]:
        """Read a single rule file and parse it.

        Args:
            file_path: Absolute path to the rule file.
            **kwargs: Backend-specific keyword arguments.

        Returns:
            A list of normalised rule items, or an empty list on error.
        """
        ...

    def validate(self, rules: Dict[str, List[T]]) -> Tuple[bool, str]:
        """Validate rules in their serialised dict form.

        Args:
            rules: The output of :meth:`as_dict`.

        Returns:
            A ``(is_valid, error_message)`` tuple.
        """
        ...

    def as_dict(self, items: List[T]) -> Dict[str, List[T]]:
        """Serialise rule items into the backend's output format."""
        ...


class AbstractRules(Generic[T]):
    """Format-agnostic rule aggregator.

    Collects rules from files and dicts, delegating format-specific parsing,
    topology injection, and validation to a pluggable :class:`RuleBackend`.
    """

    def __init__(self, backend: RuleBackend[T]):
        """Build a Rules instance.

        Args:
            backend: A :class:`RuleBackend` implementation that handles all
                format-specific logic.  Pass topology directly to the backend
                constructor (e.g. ``PrometheusRuleBackend(topology=topo)``).
        """
        self.backend = backend
        self._items: List[T] = []

    def add(
        self,
        rule_dict: Mapping[str, Any],
        **kwargs: Any,
    ) -> None:
        """Add rules from a dict to the existing ruleset.

        Args:
            rule_dict: A rule mapping in whatever format the backend accepts.
            **kwargs: Backend-specific keyword arguments forwarded to
                :meth:`RuleBackend.from_dict`.  For example, Prometheus/Loki
                backends accept ``group_name`` and ``group_name_prefix``.
        """
        self._items.extend(
            self.backend.from_dict(
                rule_dict,
                **kwargs,
            )
        )

    def add_path(self, dir_path: Union[str, Path], *, recursive: bool = False) -> None:
        """Add rules from a file or directory.

        All rules from files are aggregated into the internal ruleset.
        Group names (where applicable) are augmented with Juju topology.

        Args:
            dir_path: A rules file or a directory of rule files.
            recursive: Whether to read files recursively (no impact if
                *dir_path* is a single file).
        """
        path = Path(dir_path) if isinstance(dir_path, str) else dir_path
        if path.is_dir():
            self._items.extend(self._from_dir(path, recursive))
        elif path.is_file():
            self._items.extend(self.backend.from_file(path, root_path=path.parent))
        else:
            raise InvalidRulePathError(
                rules_absolute_path=path, message=f"Invalid rules path: {path}"
            )

    def as_dict(self) -> Dict[str, List[T]]:
        """Return the accumulated rules in the backend's output format.

        Returns:
            A dictionary whose structure depends on the backend
            (e.g. ``{"groups": [...]}`` for Prometheus).
        """
        return self.backend.as_dict(self._items) if self._items else {}

    def validate(
        self,
        rules: Mapping[str, List[T]],
    ) -> Result[T]:
        """Validate rules.

        This is a **standalone** operation — it validates the given *rules*
        without modifying the internal ruleset.

        Args:
            rules: A rule mapping in the backend's output format.

        Returns:
            A :class:`Result` with the rules and an optional
            error message.
        """
        if not rules:
            return Result(rules=self.backend.as_dict([]), errmsg=None)

        output = dict(rules)
        valid, errmsg = self.backend.validate(output)
        if not valid:
            return Result(rules=output, errmsg=errmsg)
        return Result(rules=output, errmsg=None)

    def _from_dir(self, dir_path: Path, recursive: bool) -> List[T]:
        """Read all matching rule files in a directory."""
        all_files = dir_path.glob("**/*" if recursive else "*")
        matched = sorted(
            f for f in all_files if f.is_file() and f.suffix in self.backend.file_suffixes
        )
        items: List[T] = []
        for file_path in matched:
            from_file = self.backend.from_file(file_path, root_path=dir_path)
            if from_file:
                logger.debug("Reading rule from %s", file_path)
                items.extend(from_file)
        return items


# ---------------------------------------------------------------------------
# OLDER RULES CLASS
# ---------------------------------------------------------------------------


@dataclass
class InjectResult:
    """Typed result for rule injection and validation.

    .. deprecated::
        Use :class:`Result` when switching over from Rules to AbstractRules class. This class
        will be removed in a future release.

    Attributes:
        rules: The (possibly injected) rules dictionary.
        errmsg: Optional error message produced during validation.
    """

    rules: OfficialRuleFileFormat
    errmsg: Optional[str]


class Rules:
    """Utility class for amalgamating alerting/recording rule  files and injecting juju topology.

    .. deprecated::
        Use :class:`AbstractRules` with Prometheus and Loki backends. This class will be
        removed in a future release.

    A `Rules` object supports aggregating rules from files and directories in both
    official and single rule file formats using the `add_path()` method. All the rules
    read are annotated with Juju topology labels and amalgamated into a single data structure
    in the form of a Python dictionary using the `as_dict()` method. Such a dictionary can be
    easily dumped into JSON format and exchanged over relation data. The dictionary can also
    be dumped into YAML format and written directly into a rules file that is read by
    Prometheus. Note that multiple `Rules` objects must not be written into the same file,
    since Prometheus allows only a single list of rule groups per rules file.

    The official  format is a YAML file conforming to the Prometheus/Cortex documentation
    (https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/).
    The custom single rule format is a subsection of the official YAML, having a single alert
    rule, effectively "one alert per file".
    """

    # This class uses the following terminology for the various parts of a rule file:
    # - rules file: the entire groups[] yaml, including the "groups:" key.
    # - groups (plural): the list of groups[] (a list, i.e. no "groups:" key) - it is a list
    #   of dictionaries that have the "name" and "rules" keys.
    # - group (singular): a single dictionary that has the "name" and "rules" keys.
    # - rules (plural): all the rules in a given group - a list of dictionaries of type
    #   "alert" (or "record") and "expr" keys.
    # - rule (singular): a single dictionary of type "alert" (or "record") and "expr" keys.

    def __init__(self, query_type: QueryType, topology: Optional[JujuTopology] = None):
        """Build a rule object.

        Args:
            query_type: either "promql" or "logql" to indicate the query language used
                in the rules, for manipulation with CosTool
            topology: an optional `JujuTopology` instance that is used to annotate all rules.
        """
        self.query_type = query_type
        self.topology = topology
        self.tool = CosTool(default_query_type=query_type)
        self.groups: List[OfficialRuleFileItem] = []

    @property
    def rule_type(self) -> Optional[RuleType]:
        """Return the rule type being used for interpolation in messages."""
        return None

    # --- HELPER METHODS FOR READING FILES, SHOULD BE STATIC --- #

    @staticmethod
    def _is_official_rule_format(rules_dict: Mapping[str, Any]) -> bool:
        """Are rules in the upstream format as supported by Prometheus or Loki.

        Rules in dictionary format are in "official" form if they
        contain a "groups" key, since this implies they contain a list of
        rule groups.

        Args:
            rules_dict: a set of rules in Python dictionary format

        Returns:
            True if rules are in official file format.
        """
        return "groups" in rules_dict

    @staticmethod
    def _is_single_rule_format(rules_dict: Mapping[str, Any]) -> bool:
        """Are alert rules in single rule format.

        This library supports reading of rules in a custom format that
        consists of a single rule per file. This does not conform to the
        official rule file format, which requires that each rules file
        consists of a list of rule groups and each group consists of a
        list of rules.

        Rules in dictionary form are considered to be in single rule
        format if in the least it contains two keys corresponding to the
        rule type and expression.

        Returns:
            True if rule is in single rule file format.
        """
        # one rule per file
        return "expr" in rules_dict and not RULE_TYPES.isdisjoint(rules_dict)

    @staticmethod
    def _multi_suffix_glob(
        dir_path: Path, suffixes: List[str], recursive: bool = True
    ) -> List[Path]:
        """Helper function for getting all files in a directory that have a matching suffix.

        The result is sorted to avoid unnecessary relation-get calls.

        Args:
            dir_path: path to the directory to glob from.
            suffixes: list of suffixes to include in the glob (items should begin with a period).
            recursive: a flag indicating whether a glob is recursive (nested) or not.

        Returns:
            List of files in `dir_path` that have one of the suffixes specified in `suffixes`.
        """
        all_files_in_dir = dir_path.glob("**/*" if recursive else "*")
        matched = filter(lambda f: f.is_file() and f.suffix in suffixes, all_files_in_dir)
        return sorted(matched)

    def _from_dir(self, dir_path: Path, recursive: bool) -> List[OfficialRuleFileItem]:
        """Read all rule files in a directory.

        All rules from files for the same directory are loaded into a single
        group. The generated name of this group includes juju topology.
        By default, only the top directory is scanned; for nested scanning, pass `recursive=True`.

        Args:
            dir_path: directory containing *.rule files (rules without groups).
            recursive: flag indicating whether to scan for rule files recursively.

        Returns:
            a list of dictionaries representing prometheus rule groups, each dictionary
            representing a group (structure determined by `yaml.safe_load`).
        """
        groups: List[OfficialRuleFileItem] = []

        # Gather all records into a list of groups
        for file_path in Rules._multi_suffix_glob(
            dir_path, [".rule", ".rules", ".yml", ".yaml"], recursive
        ):
            groups_from_file = self._from_file(dir_path, file_path)
            if groups_from_file:
                logger.debug("Reading rule from %s", file_path)
                groups.extend(groups_from_file)  # type: ignore

        return groups

    def _from_file(  # noqa: C901
        self, root_path: Path, file_path: Path
    ) -> List[OfficialRuleFileItem]:
        """Read a rules file from path.

        Args:
            root_path: full path to the root rules folder (used only for generating group name)
            file_path: full path to a *.rule file.

        Returns:
            A list of dictionaries representing the rules file, if file is valid (the structure is
            formed by `yaml.safe_load` of the file); an empty list otherwise.
        """
        with file_path.open() as rf:
            # Load a list of rules from file then add labels and filters
            try:
                rule_file = yaml.safe_load(rf)

            except Exception as e:
                logger.error("Failed to read rules from %s: %s", file_path.name, e)
                return []

            # Generate group name prefix
            #  - name, from juju topology
            #  - suffix, from the relative path of the rule file;
            rel_path = file_path.parent.relative_to(root_path)
            rel_path = "" if rel_path == Path(".") else str(rel_path)
            group_name_parts = [self.topology.identifier] if self.topology else []
            group_name_parts.append(rel_path)
            group_name_prefix = "_".join(filter(None, group_name_parts))

            try:
                groups = self._from_dict(
                    rule_file, group_name=file_path.stem, group_name_prefix=group_name_prefix
                )
            except ValueError as e:
                logger.error("Invalid rules file: %s (%s)", file_path.name, e)
                return []

            return groups

    def _from_dict(
        self,
        rule_dict: Mapping[str, Any],
        *,
        group_name: Optional[str] = None,
        group_name_prefix: Optional[str] = None,
        metadata: Optional[JujuTopology] = None,
    ) -> List[OfficialRuleFileItem]:
        """Process rules from dict, injecting juju topology. If a single-rule format is provided, a hash of the yaml file is injected into the group name to ensure uniqueness.

        Args:
            rule_dict: rules content in single-rule or official-rule format as a YAML dict
            group_name: a custom identifier for the rule name to include in the group name
            group_name_prefix: a custom group identifier to prefix the resulting group name, likely Juju topology and relative path context
            metadata: optional JujuTopology metadata to inject into the rules, useful if an upstream charm is providing topology
        Raises:
            ValueError, when invalid rule format given.
        """
        if not rule_dict:
            raise ValueError("Empty")

        rule_copy = copy.deepcopy(rule_dict)
        if self._is_official_rule_format(rule_copy):
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

                topology_ctx = metadata or self.topology
                if topology_ctx:
                    # only insert labels that do not already exist
                    for label, val in topology_ctx.label_matcher_dict.items():
                        if label not in rule["labels"]:
                            rule["labels"][label] = val

                    # insert juju topology filters into a prometheus rule
                    repl = r'job=~".+"' if self.query_type == "logql" else ""
                    rule["expr"] = self.tool.inject_label_matchers(
                        expression=re.sub(r"%%juju_topology%%,?", repl, rule["expr"]),
                        topology={
                            k: rule["labels"][k]
                            for k in ("juju_model", "juju_model_uuid", "juju_application")
                            if rule["labels"].get(k) is not None
                        },
                        query_type=cast(QueryType, self.query_type),
                    )

        return groups

    def _is_already_modified(self, name: str) -> bool:
        """Detect whether a group name has already been modified with juju topology."""
        modified_matcher = re.compile(r"^.*?_[\da-f]{8}_.*?rules$")
        if modified_matcher.match(name) is None:
            return False
        return True

    def _sanitize_metric_name(self, metric_name: str) -> str:
        """Sanitize a metric name according to https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels."""
        return "".join(char if re.match(r"[a-zA-Z0-9_:]", char) else "_" for char in metric_name)

    # ---- END STATIC HELPER METHODS --- #

    def add(
        self,
        rule_dict: Mapping[str, Any],
        group_name: Optional[str] = None,
        group_name_prefix: Optional[str] = None,
    ) -> None:
        """Add rules from dict to the existing ruleset.

        Args:
            rule_dict: a single-rule or official-rule mapping
            group_name: a custom group name, used only if the new rule is of single-rule format
            group_name_prefix: a custom group name prefix, used only if the new rule is of single-rule format
        """
        self.groups.extend(
            self._from_dict(rule_dict, group_name=group_name, group_name_prefix=group_name_prefix)
        )

    def add_path(self, dir_path: Union[str, Path], *, recursive: bool = False) -> None:
        """Add rules from a dir path.

        All rules from files are aggregated into a data structure representing a single rule file.
        All group names are augmented with juju topology.

        Args:
            dir_path: either a rules file or a dir of rules files.
            recursive: whether to read files recursively or not (no impact if `path` is a file).
        """
        path = Path(dir_path) if isinstance(dir_path, str) else dir_path
        if path.is_dir():
            self.groups.extend(self._from_dir(path, recursive))
        elif path.is_file():
            self.groups.extend(self._from_file(path.parent, path))  # type: ignore
        else:
            logger.debug("Rules path does not exist: %s", path)

    def as_dict(self) -> Dict[str, Any]:
        """Return standard rules file in dict representation.

        Returns:
            a dictionary containing a single list of rule groups.
            The list of rule groups is provided as value of the
            "groups" dictionary key.
        """
        return {"groups": self.groups} if self.groups else {}

    def inject_and_validate_rules(
        self, rules: Union[OfficialRuleFileFormat, SingleRuleFormat], metadata: Dict[str, str]
    ) -> InjectResult:
        """Inject Juju topology labels and validate rules using CosTool.

        Args:
            rules: a single-rule or official-rule mapping
            metadata: Juju topology metadata to inject into the rules, if
                labels are not already present
        Returns:
            An InjectResult with the possibly-injected rules and an optional
            error message if validation failed.
        """
        if not rules:
            return InjectResult(rules=OfficialRuleFileFormat(groups=[]), errmsg=None)

        topology = None
        with contextlib.suppress(KeyError):
            topology = JujuTopology.from_dict(metadata)

        # Inject juju topology labels and sanitize rules
        rules_data = OfficialRuleFileFormat(groups=self._from_dict(rules, metadata=topology))
        valid_rules, errmsg = self.tool.validate_alert_rules(rules_data)
        if not valid_rules:
            return InjectResult(rules=rules_data, errmsg=errmsg)

        return InjectResult(rules=rules_data, errmsg=None)


class AlertRules(Rules):
    """Utility class for amalgamating alerting files and injecting juju topology.

    .. deprecated::
        Use :class:`AbstractRules` with Prometheus and Loki backends. This class will be
        removed in a future release.

    The official format is a YAML file conforming to the Prometheus/Cortex documentation
    (https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/).
    The custom single rule format is a subsection of the official YAML, having a single alert
    rule, effectively "one alert per file".
    """

    pass


class RecordingRules(Rules):
    """Utility class for amalgamating recording files and injecting juju topology.

    .. deprecated::
        Use :class:`AbstractRules` with Prometheus and Loki backends. This class will be
        removed in a future release.

    The official format is a YAML file conforming to the Prometheus/Cortex documentation
    (https://prometheus.io/docs/prometheus/latest/configuration/recording_rules/).
    The custom single rule format is a subsection of the official YAML, having a single recording
    rule, effectively "one record per file".
    """

    pass
