# Copyright (c) 2024 Red Hat, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
openscap.py - Convert an OSCAL Component Definition with Trestle constructs
into a XCCDF file that can be used by OpenSCAP.
"""

import datetime
import json
import re
from typing import Dict, List, Optional
from xml.etree import ElementTree as ET

from pydantic import Field

from c2p.framework.models import Policy, PVPResult, RawResult, RuleSet, Parameter  # type: ignore
from c2p.framework.plugin_spec import (  # type: ignore
    PluginConfig,
    CollectorPluginSpec,
    GeneratorPluginSpec,
)
from c2p.framework.models.pvp_result import ObservationByRule, Subject  # type: ignore
from c2p.common.utils import get_datetime  # type: ignore

from trestle.transforms.implementations.xccdf import _XccdfResult


class PluginConfigOpenSCAP(PluginConfig):
    output: str = Field("xccdf.xml", title="Path to the generated XCCDF file")
    oval_ref: str = Field("oval.xml", title="Reference to OVAL file")
    check_to_remediation: str = Field(
        "check-remediation-mapping.json", title="Check to remediation text"
    )


ResultMapping: Dict[str, str] = {
    "fail": "failure",
    "pass": "pass",
    "fixed": "pass",
    "error": "error",
}


class CollectorPluginOpenSCAP(CollectorPluginSpec):

    def __init__(self, config: Optional[PluginConfigOpenSCAP] = None) -> None:
        super().__init__()
        self.config = config
        self.rule_subset: List[str] = []

    def set_rule_subset(self, rulesets: List[RuleSet]) -> None:
        """Generate an OpenSCAP custom profile from policy."""
        for rule in rulesets:
            self.rule_subset.append(rule.rule_id)

    def generate_pvp_result(self, raw_result: RawResult) -> PVPResult:
        """Construct a result from a Results Data stream (ARF)"""
        pvp_result: PVPResult = PVPResult()
        observations: List[ObservationByRule] = []

        co_result = _XccdfResult(raw_result.data)
        rule_use_generator = co_result.rule_use_generator()

        for rule_use in rule_use_generator:
            if self.rule_subset and rule_use.id_ not in self.rule_subset:
                continue

            # Get the original rule id
            rule_id = rule_use.idref.replace(OSCAP_RULE, "", 1)

            observation = ObservationByRule(
                rule_id=rule_id,
                methods=["AUTOMATED"],
                collected=get_datetime(),
            )

            # TODO: There are registered component. Based on the rule the plugin
            # should know the associated component and can add as a subject.
            component_subject = Subject(
                title="My Component",
                type="component",
                result=ResultMapping[rule_use.result],
                resource_id=f"{rule_use.scanner_name} {rule_use.scanner_version}",
                evaluated_on=rule_use.time,
                reason="My reason",
            )
            observation.subjects = [component_subject]
            observations.append(observation)

        pvp_result.observations_by_rule = observations
        return pvp_result


class GeneratorPluginOpenSCAP(GeneratorPluginSpec):

    def __init__(self, config: PluginConfigOpenSCAP) -> None:
        super().__init__()
        self.config = config

    # Question, do I need to create a data stream of is XCCDF enough?
    def generate_pvp_policy(self, policy: Policy):
        """Generate an OpenSCAP custom profile from policy."""
        self._generate_xccdf(policy)

    def _generate_xccdf(self, policy: Policy):
        root = _create_benchmark_xml_skeleton("someID")

        # add_reference_title_elements(root, env_yaml)
        _add_version_xml(root)
        _profile_to_xml(root, policy)
        for param in policy.parameters:
            _value_to_xml(root, param)

        check_data: Dict[str, str]
        with open(self.config.check_to_remediation) as f:
            check_data = json.load(f)

        for rule in policy.rule_sets:
            _rule_to_xml(root, rule, self.config.oval_ref, check_data)

        if hasattr(ET, "indent"):
            ET.indent(root, space="  ", level=0)

        ET.ElementTree(root).write(
            self.config.output, xml_declaration=True, encoding="utf-8"
        )


# TODO[jpower432]: Load validation compdef to get rule to check mappings
# All available checks for a component are registered here and advertise as capabilities to C2P.
# Essentially a standardized validation component is used to configure the PVP.


# Below are helper function copied from ComplianceAsCode/content/ssg

# SPDX license identifier: BSD-3-Clause
# Copyright (c) 2012-2017, Red Hat, Inc.
# All rights reserved.

XCCDF11_NS = "http://checklists.nist.gov/xccdf/1.1"
XCCDF12_NS = "http://checklists.nist.gov/xccdf/1.2"
SSG_PROJECT_NAME = "SCAP Security Guide Project"
SSG_BENCHMARK_LATEST_URI = "https://github.com/ComplianceAsCode/content/releases/latest"
OSCAP_VENDOR = "org.ssgproject"
OSCAP_BENCHMARK = "xccdf_%s.content_benchmark_" % OSCAP_VENDOR
OSCAP_VALUE = "xccdf_%s.content_value_" % OSCAP_VENDOR
xhtml_namespace = "http://www.w3.org/1999/xhtml"
SSG_XHTML_TAGS = [
    "table",
    "tr",
    "th",
    "td",
    "ul",
    "li",
    "ol",
    "p",
    "code",
    "strong",
    "b",
    "em",
    "i",
    "pre",
    "br",
    "hr",
    "small",
]
OSCAP_PROFILE = "xccdf_%s.content_profile_" % OSCAP_VENDOR
OSCAP_GROUP = "xccdf_%s.content_group_" % OSCAP_VENDOR
OSCAP_RULE = "xccdf_%s.content_rule_" % OSCAP_VENDOR
oval_namespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5"

# Source: https://github.com/ComplianceAsCode/content/blob/1956744915d8423df889d49115c486332a8327be/ssg/build_yaml.py#L414


def _create_benchmark_xml_skeleton(benchmark_id: str):
    root = ET.Element("{%s}Benchmark" % XCCDF12_NS)
    root.set("id", OSCAP_BENCHMARK + benchmark_id)
    root.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
    root.set("xsi:schemaLocation", "http://checklists.nist.gov/xccdf/1.2 xccdf-1.2.xsd")
    root.set("style", "SCAP_1.2")
    root.set("resolved", "false")
    root.set("xml:lang", "en-US")

    status = ET.SubElement(root, "{%s}status" % XCCDF12_NS)
    status.set("date", datetime.date.today().strftime("%Y-%m-%d"))
    status.text = "draft"

    add_sub_element(root, "title", XCCDF12_NS, "TestBenchmark")
    add_sub_element(root, "description", XCCDF12_NS, "My custom benchmark")
    return root


# Source: https://github.com/ComplianceAsCode/content/blob/1956744915d8423df889d49115c486332a8327be/ssg/build_yaml.py#L442C2-L500C56


def _profile_to_xml(root, policy: Policy):
    element = ET.Element("{%s}Profile" % XCCDF12_NS)
    element.set("id", OSCAP_PROFILE + "example")
    title = add_sub_element(element, "title", XCCDF12_NS, "This Exampe Profile")
    title.set("override", "true")
    desc = add_sub_element(element, "description", XCCDF12_NS, "This is a test profile")
    desc.set("override", "true")

    # Add selected rules
    for rule in policy.rule_sets:
        select = ET.Element("{%s}select" % XCCDF12_NS)
        select.set("idref", OSCAP_RULE + rule.rule_id)
        select.set("selected", "true")
        element.append(select)
    root.append(element)


def _value_to_xml(root, parameter: Parameter):
    value = ET.Element("{%s}Value" % XCCDF12_NS)
    value.set("id", OSCAP_VALUE + parameter.id)
    parameter_values = parameter.value.split(",")
    for param in parameter_values:
        value_small = ET.SubElement(value, "{%s}value" % XCCDF12_NS)
        value_small.set("selector", str(param))
        value_small.text = str(param)

    root.append(value)


def _rule_to_xml(root, ruleset: RuleSet, oval_path: str, remediation: Dict[str, str]):
    rule = ET.Element("{%s}Rule" % XCCDF12_NS)
    rule.set("selected", "false")
    rule.set("id", OSCAP_RULE + ruleset.rule_id)
    rule.set("severity", "medium")
    add_sub_element(rule, "title", XCCDF12_NS, ruleset.rule_id)
    add_sub_element(rule, "description", XCCDF12_NS, ruleset.rule_description)

    add_sub_element(rule, "rationale", XCCDF12_NS, "My rationale")

    if ruleset.check_id in remediation:
        fix_text = remediation.get(ruleset.check_id)
        fix = ET.SubElement(rule, "{%s}fix" % XCCDF12_NS)
        fix.set("system", "urn:xccdf:fix:script:sh")
        fix.text = fix_text

        # Temporarily hard-coding parameter information in the rule context
        # Need to also determine how to structure a fix to make this value last
        # value_ref = ET.SubElement(fix, "{%s}sub" % XCCDF12_NS)
        # value_ref.set("idref", OSCAP_VALUE + "client_alive_count_max")

    check_parent = rule
    check = ET.SubElement(check_parent, "{%s}check" % XCCDF12_NS)
    check.set("system", oval_namespace)
    check_export = ET.SubElement(check, "{%s}check-export" % XCCDF12_NS)

    # Temporarily hard-coding parameter information in the rule context
    check_export.set("export-name", "oval:client_alive_count_max:var:1")
    check_export.set("value-id", OSCAP_VALUE + "client_alive_count_max")

    check_content_ref = ET.SubElement(check, "{%s}check-content-ref" % XCCDF12_NS)
    check_content_ref.set("href", oval_path)
    check_content_ref.set("name", ruleset.check_id)

    root.append(rule)


def _add_version_xml(root):
    version = ET.SubElement(root, "{%s}version" % XCCDF12_NS)
    version.text = "1.0.0"
    version.set("update", SSG_BENCHMARK_LATEST_URI)


# Source: https://github.com/ComplianceAsCode/content/blob/master/ssg/entities/common.py#L89


def add_sub_element(parent, tag, ns, data):
    """
    Creates a new child element under parent with tag tag, and sets
    data as the content under the tag. In particular, data is a string
    to be parsed as an XML tree, allowing sub-elements of children to be
    added.

    If data should not be parsed as an XML tree, either escape the contents
    before passing into this function, or use ElementTree.SubElement().

    Returns the newly created subelement of type tag.
    """
    namespaced_data = add_xhtml_namespace(data)
    # This is used because our YAML data contain XML and XHTML elements
    # ET.SubElement() escapes the < > characters by &lt; and &gt;
    # and therefore it does not add child elements
    # we need to do a hack instead
    # TODO: Remove this function after we move to Markdown everywhere in SSG
    ustr = '<{0} xmlns="{3}" xmlns:xhtml="{2}">{1}</{0}>'.format(
        tag, namespaced_data, xhtml_namespace, ns
    )

    try:
        element = ET.fromstring(ustr.encode("utf-8"))
    except Exception:
        msg = "Error adding subelement to an element '{0}' from string: '{1}'".format(
            parent.tag, ustr
        )
        raise RuntimeError(msg)

    # Apart from HTML and XML elements the rule descriptions and similar
    # also contain <xccdf:sub> elements, where we need to add the prefix
    # to create a full reference.
    for x in element.findall(".//{%s}sub" % XCCDF12_NS):
        x.set("idref", OSCAP_VALUE + x.get("idref"))
        x.set("use", "legacy")
    parent.append(element)
    return element


def add_xhtml_namespace(data):
    """
    Given a xml blob, adds the xhtml namespace to all relevant tags.
    """
    # The use of lambda in the lines below is a workaround for https://bugs.python.org/issue1519638
    # I decided for this approach to avoid adding workarounds in the matching regex, this way only
    # the substituted part contains the workaround.
    # Transform <tt> in <code>
    data = re.sub(
        r"<(\/)?tt(\/)?>",
        lambda m: r"<" + (m.group(1) or "") + "code" + (m.group(2) or "") + ">",
        data,
    )
    # Adds xhtml prefix to elements: <tag>, </tag>, <tag/>
    return re.sub(
        r"<(\/)?((?:%s).*?)(\/)?>" % "|".join(SSG_XHTML_TAGS),
        lambda m: r"<"
        + (m.group(1) or "")
        + "xhtml:"
        + (m.group(2) or "")
        + (m.group(3) or "")
        + ">",
        data,
    )
