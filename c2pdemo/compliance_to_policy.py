# Copyright (c) 2024 Red Hat, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
Run C2P with the OpenSCAP plugin
"""

import os
from pathlib import Path

import fire

from c2p.framework.c2p import C2P  # type: ignore
from c2p.framework.models import PVPResult, RawResult
from c2p.framework.models.c2p_config import C2PConfig, ComplianceOscal  # type: ignore

from . import openscap  # type: ignore

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "testdata")


class OpenScapCLI:
    """
    OpenSCAPCLI is an implementation of the compliance to policy plugin for OpenSCAP.
    """

    def __init__(self, component_definition: str):
        """
        Parameters
        ----------
        socket : string
            Location of Unix Domain Socket without the unix prefix.
        """
        self.c2p_config = C2PConfig()
        self.c2p_config.compliance = ComplianceOscal()
        self.c2p_config.pvp_name = "OpenSCAP"
        self.c2p_config.result_title = "OpenSCAP Assessment Results"
        self.c2p_config.result_description = "OSCAL Assessment Results from OpenSCAP"
        self.c2p_config.compliance.component_definition = component_definition

    def generate(self, output: str, oval_reference: str) -> None:
        """
        Generate OpenSCAP policy artifacts from compliance artifacts.

        Parameters
        ----------
        output : string
            Path to generated xccdf.xml
        """
        with Path(output).open("w") as file:
            c2p = C2P(self.c2p_config)
            # Transform OSCAL (Compliance) to Policy
            config = openscap.PluginConfigOpenSCAP(
                output=file.name, oval_ref=oval_reference
            )
            openscap.GeneratorPluginOpenSCAP(config).generate_pvp_policy(
                c2p.get_policy()
            )

    def collect(self, input: str) -> None:
        """
        Collect results and transform into assessment plans.

        Parameters
        ----------
        input : string
            Path to collected results from PVP.
        """
        pvp_result: PVPResult
        with open(input, "r") as f:
            check_results = f.read()
            pvp_raw_result = RawResult(
                data=check_results
            )
            pvp_result = openscap.CollectorPluginOpenSCAP().generate_pvp_result(pvp_raw_result)

        c2p = C2P(self.c2p_config)
        c2p.set_pvp_result(pvp_result)
        oscal_assessment_results = c2p.result_to_oscal()

        print(oscal_assessment_results.oscal_serialize_json(pretty=True))


if __name__ == "__main__":
    component_definition = os.getenv(
        "TEST_COMPONENT_DEFINITION", f"{TEST_DATA_DIR}/component-definition.json"
    )
    openscapcli = OpenScapCLI(component_definition)
    fire.Fire(openscapcli)
