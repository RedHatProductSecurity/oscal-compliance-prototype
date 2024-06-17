# Copyright (c) 2024 Red Hat, Inc.
# SPDX-License-Identifier: Apache-2.0


import argparse
from pathlib import Path

from c2p.framework.c2p import C2P  # type: ignore
from c2p.framework.models.c2p_config import C2PConfig, ComplianceOscal  # type: ignore

from . import openscap  # type: ignore

TEST_DATA_DIR = 'testdata'

parser = argparse.ArgumentParser()
parser.add_argument(
    '-c',
    '--component_definition',
    type=str,
    default=f'{TEST_DATA_DIR}/component-definition.json',
    help=f'Path to component-definition.json (default: {TEST_DATA_DIR}/component-definition.json',
    required=False,
)
parser.add_argument(
    '-o',
    '--out',
    type=str,
    help='Path to generated xccdf.xml',
    required=True,
)
args = parser.parse_args()

with Path(args.out).open('w') as output:
    # Setup c2p_config
    c2p_config = C2PConfig()
    c2p_config.compliance = ComplianceOscal()
    c2p_config.compliance.component_definition = args.component_definition
    c2p_config.pvp_name = 'OpenSCAP'
    c2p_config.result_title = 'OpenSCAP Assessment Results'
    c2p_config.result_description = 'OSCAL Assessment Results from OpenSCAP'

    # Construct C2P
    c2p = C2P(c2p_config)

    # Transform OSCAL (Compliance) to Policy
    config = openscap.PluginConfigOpenSCAP(output=output.name)
    openscap.GeneratorPluginOpenSCAP(config).generate_pvp_policy(c2p.get_policy())
