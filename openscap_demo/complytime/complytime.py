# Copyright (c) 2024 Red Hat, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
Run C2P with the OpenSCAP plugin
"""

import configparser
import logging
import pathlib
import subprocess

from c2p.framework.c2p import C2P  # type: ignore
from c2p.framework.models import PVPResult, RawResult  # type: ignore
from c2p.framework.models.c2p_config import C2PConfig, ComplianceOscal  # type: ignore
from c2p.tools.viewer import viewer
from trestle.oscal.component import ComponentDefinition

import complytime.openscap as openscap  # type: ignore


class ComplyTimePrototype:
    """
    ComplyTime is an implementation of the compliance to policy.
    """

    def __init__(
        self,
        component_definition: str = "testdata/component-definition.json",
        config_path: str = "complytime.ini",
    ):
        """
        Parameters
        ----------
        component_definition : string
            Location of the product component definition to evaluate
        """
        self.component_definition = component_definition
        self.config_path = config_path

    def configure(self) -> None:
        """
        Determine the plugin and component definition per the component definitions and create a config.
        We are hard coding OpenSCAP as the plugin of course and running with that.
        """
        global_config = configparser.ConfigParser(
            interpolation=configparser.ExtendedInterpolation()
        )
        global_config["OpenSCAP"] = {
            "results-title": "",
            "results-description": "",
            "check_to_remediation": "",
            "oval_ref": "",
            "output": "",
        }
        with open(self.config_path, "w") as configfile:
            global_config.write(configfile)

    def _read_config(self) -> configparser.SectionProxy:
        """Read C2P config"""
        global_config = configparser.ConfigParser(
            interpolation=configparser.ExtendedInterpolation()
        )
        global_config.read(self.config_path)
        config_section = global_config["OpenSCAP"]
        return config_section

    def _create_c2p_config(self) -> C2PConfig:
        c2p_config = C2PConfig()
        c2p_config.compliance = ComplianceOscal()
        config_section = self._read_config()
        c2p_config.pvp_name = "OpenSCAP"
        c2p_config.result_title = config_section["results-title"]
        c2p_config.result_description = config_section["results-description"]
        c2p_config.compliance.component_definition = self.component_definition
        return c2p_config

    def generate(self, profile: str = "nist-high") -> None:
        """
        Generate OpenSCAP policy artifacts from compliance artifacts.

        Parameters
        ----------
        profile : string
            Policy implementation to evaluate
        """
        c2p_config = self._create_c2p_config()
        c2p = C2P(c2p_config)
        config = self._read_config()
        oscap = openscap.GeneratorPluginOpenSCAP(config)
        oscap.generate_pvp_policy(policy=c2p.get_policy())

    def run(self, fix: bool = False) -> None:
        command = [
            "oscap",
            "xccdf",
            "eval",
            "--profile",
            "profile_example",
            "--results",
            "results.xml",
        ]
        if fix:
            command.append("--remediate")
        config = self._read_config()
        command.append(config["output"])
        subprocess.run(command)
        logging.info("Writing results to results.xml")

    def collect(self, to_markdown: bool = False) -> None:
        """
        Collect results and optionally transform into an assessment result.

        Parameters
        ----------
        to_markdown : bool
            Optionally transform into Markdown

        """
        c2p_config = self._create_c2p_config()
        c2p = C2P(c2p_config)
        config = self._read_config()

        pvp_raw_result: RawResult
        with open('results.xml', "r") as f:
            check_results = f.read()
            pvp_raw_result = RawResult(data=check_results)

        print(pvp_raw_result)

        oscap = openscap.CollectorPluginOpenSCAP(config=config)
        pvp_result: PVPResult = oscap.generate_pvp_result(pvp_raw_result)

        c2p = C2P(c2p_config)
        c2p.set_pvp_result(pvp_result)
        oscal_assessment_results = c2p.result_to_oscal()

        print(oscal_assessment_results.oscal_serialize_json(pretty=True))

        if to_markdown:
            compdef = ComponentDefinition.oscal_read(pathlib.Path(self.component_definition))
            rendered_md = viewer.render(oscal_assessment_results, compdef)
            pathlib.Path('results.md').open('w').write(rendered_md)
