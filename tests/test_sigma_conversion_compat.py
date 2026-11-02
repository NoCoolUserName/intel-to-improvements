"""Review gate for generated raw-event Splunk searches.

These are converter output checks, not evidence of execution in Splunk. Changes to
the snapshot require a source-rule and Splunk operator-semantics review.
"""

import json
from pathlib import Path

import pytest
import yaml

from iti import detection
from iti.store import digest


FIELD_MAP = {
    "Image": "process_path",
    "CommandLine": "command_line",
    "OriginalFileName": "original_name",
}
BASELINE = json.loads(
    (Path(__file__).parent / "fixtures" / "splunk_conversion_baseline.json").read_text()
)


@pytest.mark.parametrize("rule_id", sorted(BASELINE))
def test_pinned_sigma_rule_query_snapshot(rule_id):
    rule, raw, source = next(
        row for row in detection.catalog() if str(row[0]["id"]) == rule_id
    )
    assert digest(raw) == source["sha256"] == BASELINE[rule_id]["source_sha256"]
    assert rule["detection"]["condition"] == BASELINE[rule_id]["condition"]
    assert detection.convert(raw, FIELD_MAP) == BASELINE[rule_id]["queries"]


def _rule(selectors):
    return yaml.safe_dump({
        "title": "Converter regression fixture",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": selectors,
    })


def test_field_mapping_selector_and_operators():
    raw = _rule({
        "selection": {
            "Image|endswith": r"\certutil.exe",
            "CommandLine|contains|all": ["-urlcache", "-split"],
        },
        "condition": "selection",
    })
    query, = detection.convert(raw, FIELD_MAP)
    assert query == (
        'command_line="*-urlcache*" command_line="*-split*" '
        'process_path="*\\\\certutil.exe"'
    )
    assert "Image=" not in query and "CommandLine=" not in query


def test_boolean_selectors_negation_and_regex_pipeline():
    raw = _rule({
        "selection": {"Image|endswith": r"\certutil.exe"},
        "filter": {"CommandLine|contains": "-store"},
        "condition": "selection and not filter",
    })
    assert detection.convert(raw, FIELD_MAP) == [
        'process_path="*\\\\certutil.exe" NOT command_line="*-store*"'
    ]
    regex = _rule({"selection": {"CommandLine|re": "(?i)certutil"}, "condition": "selection"})
    assert detection.convert(regex, FIELD_MAP) == [
        '*\n| regex command_line="(?i)certutil"'
    ]


def test_invalid_selector_reports_conversion_failure():
    raw = _rule({"selection": {"Image": "certutil.exe"}, "condition": "missing"})
    with pytest.raises(Exception, match="Detection 'missing' not defined"):
        detection.convert(raw, FIELD_MAP)
