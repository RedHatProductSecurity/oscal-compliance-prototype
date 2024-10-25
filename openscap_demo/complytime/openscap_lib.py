# Copyright (c) 2024 Red Hat, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
openscap.py - Convert an OSCAL Component Definition with Trestle constructs
into a XCCDF file that can be used by OpenSCAP.
"""

import datetime
import re
from typing import Dict
from xml.etree import ElementTree as ET

from c2p.framework.models.models_pb2 import Policy, Rule, Parameter  # type: ignore

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
var_replace_prefix = "xccdf_var"

# Source: https://github.com/ComplianceAsCode/content/blob/1956744915d8423df889d49115c486332a8327be/ssg/build_yaml.py#L414


def create_benchmark_xml_skeleton(benchmark_id: str):
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


def profile_to_xml(root, policy: Policy):
    element = ET.Element("{%s}Profile" % XCCDF12_NS)
    element.set("id", OSCAP_PROFILE + "example")
    title = add_sub_element(element, "title", XCCDF12_NS, "This Example Profile")
    title.set("override", "true")
    desc = add_sub_element(element, "description", XCCDF12_NS, "This is a test profile")
    desc.set("override", "true")

    # Add selected rules
    for rule in policy.rules:
        select = ET.Element("{%s}select" % XCCDF12_NS)
        select.set("idref", OSCAP_RULE + rule.name)
        select.set("selected", "true")
        element.append(select)
    root.append(element)


def value_to_xml(root, parameter: Parameter):
    value = ET.Element("{%s}Value" % XCCDF12_NS)
    value.set("id", OSCAP_VALUE + parameter.name)
    parameter_values = parameter.selected_value.split(",")
    for param in parameter_values:
        value_small = ET.SubElement(value, "{%s}value" % XCCDF12_NS)
        value_small.set("selector", str(param))
        value_small.text = str(param)

    root.append(value)


def rule_to_xml(root, ruleset: Rule, oval_path: str, remediation: Dict[str, str]):
    rule = ET.Element("{%s}Rule" % XCCDF12_NS)
    rule.set("selected", "false")
    rule.set("id", OSCAP_RULE + ruleset.name)
    rule.set("severity", "medium")
    add_sub_element(rule, "title", XCCDF12_NS, ruleset.name)
    add_sub_element(rule, "description", XCCDF12_NS, ruleset.description)

    add_sub_element(rule, "rationale", XCCDF12_NS, "My rationale")

    if ruleset.check.name in remediation:
        fix_text = remediation.get(ruleset.check.name, "")
        fix = ET.SubElement(rule, "{%s}fix" % XCCDF12_NS)
        fix.set("system", "urn:xccdf:fix:script:sh")
        fix.text = fix_text

        if ruleset.parameter:
            value_ref = ET.Element("{%s}sub" % XCCDF12_NS)
            value_ref.set("idref", OSCAP_VALUE + ruleset.parameter.name)
            parts = re.split(var_replace_prefix, fix_text)

            if parts:
                fix.text = parts[0]
                text_after_vars = parts[1]
                xccdfvarsub = ET.SubElement(
                    fix,
                    "{%s}sub" % XCCDF12_NS,
                    idref=OSCAP_VALUE + ruleset.parameter.name,
                )
                xccdfvarsub.tail = text_after_vars
                xccdfvarsub.set("use", "legacy")

    check_parent = rule
    check = ET.SubElement(check_parent, "{%s}check" % XCCDF12_NS)
    check.set("system", oval_namespace)

    if ruleset.parameter:
        check_export = ET.SubElement(check, "{%s}check-export" % XCCDF12_NS)
        check_export.set("export-name", "oval:%s:var:1" % ruleset.parameter.name)
        check_export.set("value-id", OSCAP_VALUE + ruleset.parameter.name)

    check_content_ref = ET.SubElement(check, "{%s}check-content-ref" % XCCDF12_NS)
    check_content_ref.set("href", oval_path)
    check_content_ref.set("name", ruleset.check.name)

    root.append(rule)


def add_version_xml(root):
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
