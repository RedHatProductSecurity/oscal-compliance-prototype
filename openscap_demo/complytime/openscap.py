#!/usr/bin/env python
# sample_openscap_plugin.py

import json
import logging
import os
import pathlib
import subprocess
from typing import Dict, List
from xml.etree import ElementTree as ET

from c2p.framework.models import RawResult  # type: ignore
from c2p.framework.plugin_spec import PluginSpec  # type: ignore
from c2p.framework.models.models_pb2 import (
    ObservationByCheck,
    Result,
    PVPResult,
    Policy,
    Subject,
)
import c2p.framework.models.scanner_pb2_grpc as pb2_grpc  # type: ignore
import c2p.framework.models.messages_pb2 as messages_pb2  # type: ignore
from c2p.common.utils import get_datetime  # type: ignore

from trestle.transforms.implementations.xccdf import _XccdfResult

# gRPC and generated classes
from concurrent import futures
import grpc  # type: ignore

import complytime.openscap_lib as openscap_lib  # type: ignore

schema = """b{
  "title": "Configuration Schema",
  "type": "object",
  "properties": {
    "server": {
      "type": "object",
      "properties": {
        "host": {
          "type": "string"
        },
        "port": {
          "type": "integer"
        },
        "timeout": {
          "type": "number"
        }
      }
    },
    "logging": {
      "type": "object",
      "properties": {
        "level": {
          "type": "string",
          "enum": ["debug", "info", "warning", "error", "critical"]
        },
        "file": {
          "type": "string"
        }
      }
    }
  }
}"""

ResultMapping = {
    "fixed": Result.RESULT_PASS,
    "pass": Result.RESULT_PASS,
    "fail": Result.RESULT_ERROR,
    "error": Result.RESULT_ERROR,
    "notchecked": Result.RESULT_ERROR,
}


class OpenSCAP(PluginSpec):
    def __init__(self, config: Dict, workspace: str) -> None:
        super().__init__()
        self.config = config
        self.workspace = workspace

    def generate_pvp_policy(self, policy: Policy):
        """Generate an OpenSCAP custom profile from policy."""
        self._generate_xccdf(policy)

    def _generate_xccdf(self, policy: Policy):
        """Generate an OpenSCAP custom profile from policy."""
        root = openscap_lib.create_benchmark_xml_skeleton("someID")

        # add_reference_title_elements(root, env_yaml)
        openscap_lib.add_version_xml(root)
        openscap_lib.profile_to_xml(root, policy)
        for param in policy.parameters:
            openscap_lib.value_to_xml(root, param)

        check_data: Dict[str, str]
        with open(self.config["check_to_remediation"]) as f:
            check_data = json.load(f)

        for rule in policy.rules:
            oval_path = os.path.abspath(self.config["oval_ref"])
            openscap_lib.rule_to_xml(root, rule, oval_path, check_data)

        if hasattr(ET, "indent"):
            ET.indent(root, space="  ", level=0)

        policy_output = os.path.join(self.workspace, self.config["output"])
        ET.ElementTree(root).write(
            policy_output, xml_declaration=True, encoding="utf-8"
        )

    def generate_pvp_result(self, raw_result: RawResult) -> PVPResult:
        """Construct a result from XCCDF Results."""
        observations: List[ObservationByCheck] = []

        co_result = _XccdfResult(raw_result.data)
        rule_use_generator = co_result.rule_use_generator()

        for rule_use in rule_use_generator:
            # Get the original rule id
            rule_id = rule_use.idref.replace(openscap_lib.OSCAP_RULE, "", 1)
            print(rule_use.idref)
            check_id = rule_use.idref.replace(openscap_lib.OSCAP_VALUE, "", 1)

            component_subject = Subject(
                title="My Component",
                result=ResultMapping[rule_use.result],
                resource_id=f"{rule_use.scanner_name} {rule_use.scanner_version}",
                evaluated_on=get_datetime(),
                reason="My reason",
            )

            observation = ObservationByCheck(
                name=rule_id,
                check_id=check_id,
                methods=["AUTOMATED"],
                collected_at=get_datetime(),
                subjects=[component_subject],
            )
            observations.append(observation)

        pvp_result = PVPResult(observations=observations)
        return pvp_result


class OpenSCAPProviderServicer(pb2_grpc.ScanningProviderServicer):
    def __init__(self):
        self.config: Dict = {}
        self.plugin_id = "OpenSCAP"
        self.plugin_workspace = ""

    def GetSchema(
        self, request: messages_pb2.GetSchemaRequest, context
    ) -> messages_pb2.GetSchemaResponse:
        """Implemented Get Schema."""
        return messages_pb2.GetSchemaResponse(
            json_schema=bytes(schema, encoding="utf8")
        )

    def UpdateConfiguration(
        self, request: messages_pb2.ConfigureRequest, context
    ) -> messages_pb2.ConfigureResponse:
        """Implemented Update Configuration."""
        self.config = json.loads(request.config)
        user_workspace = self.config["workspace"]
        self.plugin_workspace = os.path.join(user_workspace, self.plugin_id)
        pathlib.Path(self.plugin_workspace).mkdir(exist_ok=True)
        return messages_pb2.ConfigureResponse(error="I have been configured.")

    def Generate(
        self, request: messages_pb2.GenerateRequest, context
    ) -> messages_pb2.GenerateResponse:
        """Implemented Generate"""
        generator = OpenSCAP(self.config, self.plugin_workspace)
        generator.generate_pvp_policy(request.policy)
        logging.info(f"I have generated some policy {self.plugin_workspace}")
        return messages_pb2.GenerateResponse(error="")

    def Scan(
        self, request: messages_pb2.ScanRequest, context
    ) -> messages_pb2.ScanResponse:
        """Implemented Scan."""
        policy_output = os.path.join(self.plugin_workspace, self.config["output"])
        results_output = os.path.join(self.plugin_workspace, "arf.xml")
        command = [
            "oscap",
            "xccdf",
            "eval",
            "--profile",
            "profile_example",
            "--results",
            results_output,
            policy_output,
        ]
        subprocess.run(command)

        pvp_raw_result: RawResult
        with open(results_output, "r") as f:
            check_results = f.read()
            pvp_raw_result = RawResult(data=check_results)

        oscap = OpenSCAP(self.config, self.plugin_workspace)
        pvp_result: PVPResult = oscap.generate_pvp_result(pvp_raw_result)
        logging.info("I have scanned")
        return messages_pb2.ScanResponse(result=pvp_result, error="")


def create_server(uds_address):
    server = grpc.server(futures.ThreadPoolExecutor())
    pb2_grpc.add_ScanningProviderServicer_to_server(OpenSCAPProviderServicer(), server)
    server.add_insecure_port(uds_address)
    return server


def serve(server):
    server.start()
    server.wait_for_termination()


def main():
    uds_address = os.environ.get("UDS_ADDRESS")
    server = create_server(uds_address)
    serve(server)
