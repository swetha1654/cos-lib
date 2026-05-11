# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for SigmaRuleBackend (from_dict, validate, as_dict, file_suffixes)."""

import unittest

from helpers import make_topology

from cosl.backends.sigma import SigmaRuleBackend
from cosl.rules import AbstractRules


# A minimal valid Sigma rule dict
VALID_SIGMA_RULE = {
    "title": "Test Sigma Rule",
    "logsource": {"category": "process_creation", "product": "windows"},
    "detection": {
        "selection": {"CommandLine|contains": "mimikatz"},
        "condition": "selection",
    },
    "level": "high",
}

# A second valid rule for multi-rule tests
VALID_SIGMA_RULE_2 = {
    "title": "Another Sigma Rule",
    "logsource": {"category": "network_connection", "product": "linux"},
    "detection": {
        "selection": {"DestinationPort": 4444},
        "condition": "selection",
    },
    "level": "critical",
}

# A rule missing required fields
INCOMPLETE_SIGMA_RULE = {
    "title": "Incomplete Rule",
}


# ===================================================================
# SigmaRuleBackend – from_dict
# ===================================================================


class TestSigmaBackendFromDict(unittest.TestCase):
    """Tests for SigmaRuleBackend.from_dict."""

    def test_valid_rule_parsed(self):
        """A valid Sigma rule dict is parsed into a single-item list."""
        backend = SigmaRuleBackend()
        result = backend.from_dict(VALID_SIGMA_RULE)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["title"], "Test Sigma Rule")

    def test_empty_dict_raises(self):
        """An empty dict raises ValueError."""
        backend = SigmaRuleBackend()
        with self.assertRaises(ValueError) as ctx:
            backend.from_dict({})
        self.assertEqual(str(ctx.exception), "Empty")

    def test_missing_required_fields_raises(self):
        """A rule missing required fields raises ValueError."""
        backend = SigmaRuleBackend()
        with self.assertRaises(ValueError) as ctx:
            backend.from_dict(INCOMPLETE_SIGMA_RULE)
        self.assertIn("logsource", str(ctx.exception))
        self.assertIn("detection", str(ctx.exception))

    def test_missing_title_raises(self):
        """A rule missing 'title' raises ValueError."""
        backend = SigmaRuleBackend()
        rule = {"logsource": {"category": "test"}, "detection": {"condition": "selection"}}
        with self.assertRaises(ValueError) as ctx:
            backend.from_dict(rule)
        self.assertIn("title", str(ctx.exception))

    def test_topology_injected_as_tags(self):
        """Topology labels are injected as tags."""
        topo = make_topology()
        backend = SigmaRuleBackend(topology=topo)
        result = backend.from_dict(VALID_SIGMA_RULE)
        tags = result[0]["tags"]
        self.assertIn("juju_model=mymodel", tags)
        self.assertIn("juju_application=myapp", tags)

    def test_topology_preserves_existing_tags(self):
        """Existing tags are preserved when topology is injected."""
        topo = make_topology()
        backend = SigmaRuleBackend(topology=topo)
        rule = {**VALID_SIGMA_RULE, "tags": ["attack.execution"]}
        result = backend.from_dict(rule)
        tags = result[0]["tags"]
        self.assertIn("attack.execution", tags)
        self.assertIn("juju_model=mymodel", tags)

    def test_topology_does_not_duplicate_tags(self):
        """Tags already present are not duplicated."""
        topo = make_topology()
        backend = SigmaRuleBackend(topology=topo)
        rule = {**VALID_SIGMA_RULE, "tags": ["juju_model=mymodel"]}
        result = backend.from_dict(rule)
        tags = result[0]["tags"]
        self.assertEqual(tags.count("juju_model=mymodel"), 1)

    def test_no_topology_no_tags_added(self):
        """Without topology, no tags are injected."""
        backend = SigmaRuleBackend()
        result = backend.from_dict(VALID_SIGMA_RULE)
        # Original rule has no tags
        self.assertNotIn("tags", result[0])

    def test_from_dict_does_not_mutate_input(self):
        """from_dict does not mutate the original rule dict."""
        backend = SigmaRuleBackend(topology=make_topology())
        original = {**VALID_SIGMA_RULE}
        backend.from_dict(original)
        # Original should not have topology tags
        self.assertNotIn("tags", original)


# ===================================================================
# SigmaRuleBackend – validate
# ===================================================================


class TestSigmaBackendValidate(unittest.TestCase):
    """Tests for SigmaRuleBackend.validate using pySigma."""

    def test_valid_rule_passes(self):
        """A valid Sigma rule passes validation."""
        backend = SigmaRuleBackend()
        rules = {"rules": [VALID_SIGMA_RULE]}
        valid, errmsg = backend.validate(rules)
        self.assertTrue(valid)
        self.assertEqual(errmsg, "")

    def test_multiple_valid_rules_pass(self):
        """Multiple valid rules all pass validation."""
        backend = SigmaRuleBackend()
        rules = {"rules": [VALID_SIGMA_RULE, VALID_SIGMA_RULE_2]}
        valid, errmsg = backend.validate(rules)
        self.assertTrue(valid)
        self.assertEqual(errmsg, "")

    def test_empty_rules_list_passes(self):
        """An empty rules list passes validation (nothing to validate)."""
        backend = SigmaRuleBackend()
        rules = {"rules": []}
        valid, errmsg = backend.validate(rules)
        self.assertTrue(valid)
        self.assertEqual(errmsg, "")

    def test_missing_rules_key_passes(self):
        """A dict without a 'rules' key passes (nothing to iterate)."""
        backend = SigmaRuleBackend()
        valid, errmsg = backend.validate({})
        self.assertTrue(valid)
        self.assertEqual(errmsg, "")

    def test_invalid_detection_fails(self):
        """A rule with an invalid detection section fails validation."""
        backend = SigmaRuleBackend()
        rule = {
            "title": "Bad Detection",
            "logsource": {"category": "test"},
            "detection": {"condition": "nonexistent_selection"},
        }
        rules = {"rules": [rule]}
        valid, errmsg = backend.validate(rules)
        self.assertFalse(valid)
        self.assertIn("Bad Detection", errmsg)

    def test_multiple_errors_collected(self):
        """Errors from multiple invalid rules are all reported."""
        backend = SigmaRuleBackend()
        bad_rule_1 = {
            "title": "Bad Rule 1",
            "logsource": {"category": "test"},
            "detection": {"condition": "missing_ref"},
        }
        bad_rule_2 = {
            "title": "Bad Rule 2",
            "logsource": {"category": "test"},
            "detection": {"condition": "another_missing"},
        }
        rules = {"rules": [bad_rule_1, bad_rule_2]}
        valid, errmsg = backend.validate(rules)
        self.assertFalse(valid)
        self.assertIn("Bad Rule 1", errmsg)
        self.assertIn("Bad Rule 2", errmsg)

    def test_error_uses_title_as_label(self):
        """Error messages reference the rule title."""
        backend = SigmaRuleBackend()
        rule = {
            "title": "My Specific Rule",
            "logsource": {"category": "test"},
            "detection": {"condition": "bad_ref"},
        }
        rules = {"rules": [rule]}
        valid, errmsg = backend.validate(rules)
        self.assertFalse(valid)
        self.assertIn("My Specific Rule", errmsg)

    def test_error_uses_index_when_no_title(self):
        """Error messages use rule index when title is missing."""
        backend = SigmaRuleBackend()
        rule = {
            "logsource": {"category": "test"},
            "detection": {"condition": "bad_ref"},
        }
        rules = {"rules": [rule]}
        valid, errmsg = backend.validate(rules)
        self.assertFalse(valid)
        self.assertIn("rule #0", errmsg)

    def test_valid_and_invalid_mixed(self):
        """When mixing valid and invalid rules, only invalid ones are reported."""
        backend = SigmaRuleBackend()
        bad_rule = {
            "title": "Bad Rule",
            "logsource": {"category": "test"},
            "detection": {"condition": "nonexistent"},
        }
        rules = {"rules": [VALID_SIGMA_RULE, bad_rule]}
        valid, errmsg = backend.validate(rules)
        self.assertFalse(valid)
        self.assertIn("Bad Rule", errmsg)
        self.assertNotIn("Test Sigma Rule", errmsg)


# ===================================================================
# SigmaRuleBackend – as_dict and file_suffixes
# ===================================================================


class TestSigmaBackendOther(unittest.TestCase):
    """Tests for as_dict and file_suffixes."""

    def test_as_dict_wraps_under_rules_key(self):
        """as_dict wraps items under a 'rules' key."""
        backend = SigmaRuleBackend()
        items = backend.from_dict(VALID_SIGMA_RULE)
        result = backend.as_dict(items)
        self.assertIn("rules", result)
        self.assertEqual(len(result["rules"]), 1)

    def test_as_dict_empty_returns_empty_dict(self):
        """as_dict with no items returns an empty dict."""
        backend = SigmaRuleBackend()
        result = backend.as_dict([])
        self.assertEqual(result, {})

    def test_file_suffixes(self):
        """file_suffixes returns yml and yaml."""
        backend = SigmaRuleBackend()
        self.assertEqual(backend.file_suffixes, [".yml", ".yaml"])


# ===================================================================
# SigmaRuleBackend – integration with AbstractRules
# ===================================================================


class TestSigmaAbstractRulesIntegration(unittest.TestCase):
    """Tests for SigmaRuleBackend used via AbstractRules."""

    def test_add_and_as_dict(self):
        """Adding a rule via AbstractRules and retrieving via as_dict works."""
        rules = AbstractRules(backend=SigmaRuleBackend())
        rules.add(VALID_SIGMA_RULE)
        result = rules.as_dict()
        self.assertIn("rules", result)
        self.assertEqual(len(result["rules"]), 1)
        self.assertEqual(result["rules"][0]["title"], "Test Sigma Rule")

    def test_add_multiple(self):
        """Multiple adds accumulate rules."""
        rules = AbstractRules(backend=SigmaRuleBackend())
        rules.add(VALID_SIGMA_RULE)
        rules.add(VALID_SIGMA_RULE_2)
        result = rules.as_dict()
        self.assertEqual(len(result["rules"]), 2)

    def test_validate_valid_rules(self):
        """Validation of valid rules returns no error."""
        rules = AbstractRules(backend=SigmaRuleBackend())
        rules.add(VALID_SIGMA_RULE)
        result = rules.validate(rules.as_dict())
        self.assertIsNone(result.errmsg)

    def test_validate_invalid_rules(self):
        """Validation of invalid rules returns an error message."""
        backend = SigmaRuleBackend()
        rules = AbstractRules(backend=backend)
        bad_rules = {
            "rules": [
                {
                    "title": "Invalid",
                    "logsource": {"category": "test"},
                    "detection": {"condition": "missing"},
                }
            ]
        }
        result = rules.validate(bad_rules)
        self.assertIsNotNone(result.errmsg)
        self.assertIn("Invalid", result.errmsg)

    def test_as_dict_empty_when_no_rules(self):
        """as_dict returns empty dict when no rules added."""
        rules = AbstractRules(backend=SigmaRuleBackend())
        self.assertEqual(rules.as_dict(), {})

    def test_with_topology(self):
        """Rules added with topology backend get tags injected."""
        topo = make_topology()
        rules = AbstractRules(backend=SigmaRuleBackend(topology=topo))
        rules.add(VALID_SIGMA_RULE)
        result = rules.as_dict()
        tags = result["rules"][0]["tags"]
        self.assertIn("juju_model=mymodel", tags)


if __name__ == "__main__":
    unittest.main()
