# Copyright (c) 2024 Red Hat, Inc.
# SPDX-License-Identifier: Apache-2.0


"""
Run C2P with the OpenSCAP plugin
"""

import configparser
import json
import logging
import os
import subprocess
import time

import grpc

from c2p.framework.c2p import C2P  # type: ignore
from c2p.framework.models.c2p_config import C2PConfig, ComplianceOscal  # type: ignore
import c2p.framework.models.scanner_pb2_grpc as pb2_grpc  # type: ignore
import c2p.framework.models.messages_pb2 as messages_pb2  # type: ignore
import c2p.framework.oscal_utils as oscal_utils


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


class ComplyTimeClient:
    """
    ComplyTime is an implementation of the compliance to policy.
    """

    def __init__(
        self,
        address: str,
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
        self.address = address

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

    def _get_schema(self) -> None:
        """Get the plugin schema for configuring the plugin"""
        req = messages_pb2.GetSchemaRequest()

        with grpc.insecure_channel(self.address) as channel:
            stub = pb2_grpc.ScanningProviderStub(channel)
            resp = stub.GetSchema(req)
            print(resp)

    def _read_config(self) -> configparser.SectionProxy:
        """Read C2P config"""
        global_config = configparser.ConfigParser(
            interpolation=configparser.ExtendedInterpolation()
        )
        global_config.read(self.config_path)
        config_section = global_config["OpenSCAP"]
        return config_section

    def _configure(self) -> None:
        """Configure the plugin with user configuration."""

        config_section = self._read_config()
        plain_dict = {}

        for key, value in config_section.items():
            plain_dict[key] = value

        configuration = json.dumps(plain_dict)
        config = bytes(configuration, encoding="utf8")
        req = messages_pb2.ConfigureRequest(config=config)

        with grpc.insecure_channel(self.address) as channel:
            stub = pb2_grpc.ScanningProviderStub(channel)
            resp: messages_pb2.ConfigureResponse = stub.UpdateConfiguration(req)
            logging.info(resp.error)

    def _start_process(self) -> subprocess.Popen:
        try:
            command = ["openscap-service"]
            environment = os.environ.copy()
            environment["UDS_ADDRESS"] = self.address
            process = subprocess.Popen(command, shell=True, env=environment)
            logging.info(f"Process started with PID: {process.pid}")
            time.sleep(5)
            return process
        except subprocess.CalledProcessError as e:
            logging.error(f"Error starting process: {e}")
            return None

    def _kill_process(self, process: subprocess.Popen):
        if process is not None and process.poll() is None:
            try:
                process.terminate()
                process.wait()
                logging.info("Process terminated successfully.")
            except subprocess.TimeoutExpired:
                logging.warning("Process termination timed out.")
                process.kill()
        else:
            logging.info("Process is already terminated or not running.")

    def generate(self, profile: str) -> None:
        """
        Generate some policy and stuff
        """
        try:
            logging.info(f"processing profile {profile}")
            c2p_config = self._create_c2p_config()
            c2p = C2P(c2p_config)

            process = self._start_process()
            self._configure()
            req = messages_pb2.GenerateRequest(policy=c2p.get_policy())
            with grpc.insecure_channel(self.address) as channel:
                stub = pb2_grpc.ScanningProviderStub(channel)
                resp: messages_pb2.GenerateResponse = stub.Generate(req)
                if resp.error:
                    logging.error(resp.error)
        finally:
            self._kill_process(process)

    def scan(self) -> None:
        """Scanning some things."""
        try:
            process = self._start_process()
            self._configure()
            c2p_config = self._create_c2p_config()
            c2p = C2P(c2p_config)

            req = messages_pb2.ScanRequest()
            with grpc.insecure_channel(self.address) as channel:
                stub = pb2_grpc.ScanningProviderStub(channel)
                resp: messages_pb2.ScanResponse = stub.Scan(req)
                if resp.error:
                    logging.error(resp.error)
                c2p.set_pvp_result(resp.result)
        finally:
            self._kill_process(process)

        oscal_assessment_results = c2p.result_to_oscal()
        assessment_file = f"assessment-results{oscal_utils.get_datetime()}.json"
        with open(assessment_file, "w") as file:
            file.write(oscal_assessment_results.oscal_serialize_json(pretty=True))

    def _create_c2p_config(self) -> C2PConfig:
        c2p_config = C2PConfig()
        c2p_config.compliance = ComplianceOscal()
        config_section = self._read_config()
        c2p_config.pvp_name = "OpenSCAP"
        c2p_config.result_title = config_section["results-title"]
        c2p_config.result_description = config_section["results-description"]
        c2p_config.compliance.component_definition = self.component_definition
        return c2p_config
