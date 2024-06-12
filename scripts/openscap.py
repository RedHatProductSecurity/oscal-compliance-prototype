# Copyright (c) 2024 Red Hat, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
openscap.py - Convert an OSCAL Component Definition with Trestle constructs
into a XCCDF file that can be used by OpenSCAP.
"""

import base64
import bz2
from typing import List, Optional

from pydantic import Field

from c2p.framework.models import Policy, PVPResult, RawResult  # type: ignore
from c2p.framework.plugin_spec import PluginConfig, PluginSpec  # type: ignore
from c2p.framework.models.pvp_result import ObservationByCheck, Subject  # type: ignore
from c2p.common.utils import get_datetime  # type: ignore

from trestle.transforms.implementations.xccdf import _XccdfResult


class PluginConfigOpenSCAP(PluginConfig):
    output: str = Field("xccdf.xml", title="Path to the generated XCCDF file")


class PluginOpenSCAP(PluginSpec):

    def __init__(self, config: Optional[PluginConfigOpenSCAP] = None) -> None:
        super().__init__()
        self.config = config

    def generate_pvp_policy(self, policy: Policy):
        """Generate an OpenSCAP custom profile from policy."""
        pass

    def generate_pvp_result(self, raw_result: RawResult) -> PVPResult:
        """Construct a result from a Results Data stream (ARF)"""
        pvp_result: PVPResult = PVPResult()
        observations: List[ObservationByCheck] = []

        if not raw_result.data.startswith("<?xml"):
            raw_result.data = bz2.decompress(base64.b64decode(raw_result))
        co_result = _XccdfResult(raw_result.data)

        rule_use_generator = co_result.rule_use_generator()

        for rule_use in rule_use_generator:
            observation = ObservationByCheck(
                check_id=rule_use.idref,
                methods=["AUTOMATED"],
                collected=get_datetime()
            )
            observation.subjects = Subject(
                title=f"{rule_use.scanner_name} {rule_use.scanner_version}",
                type="resource",
                result=rule_use.result,
                resource_id=rule_use.id_,
                evaluated_on=rule_use.time,
                reason="",
            )
            observations.append(observation)

        pvp_result.observations_by_check = observations
        return pvp_result
