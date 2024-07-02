"""
This module handles the compliance to policy transformation.
"""

import argparse 

from c2p.framework.c2p import C2P
from c2p.framework.models.c2p_config import C2PConfig, ComplianceOscal

from bash_plugin import BashPluginConfig, BashPlugin


parser = argparse.ArgumentParser()
parser.add_argument(
    '-c',
    '--component-definition',
    type=str,
    default='./component-definition.json',
    help=f'Path to component definition JSON file.',
    required=False,
)
parser.add_argument(
    '-o',
    '--output-file',
    type=str,
    default='./sshd-check.config',
    help=f'Path to output results file.',
    required=False,
)

def main():
    """
    Executes the compliance to policy command.
    """
    args = parser.parse_args()
    c2p_config = C2PConfig()
    c2p_config.compliance = ComplianceOscal()
    c2p_config.compliance.component_definition = args.component_definition
    c2p_config.pvp_name = 'BashExample'
    c2p_config.result_title = 'Bash Example Assessment Results'
    c2p_config.result_description = 'OSCAL Assessment Results from Bash Example'

    c2p = C2P(c2p_config)
    config = BashPluginConfig(output_file=args.output_file)
    policy = c2p.get_policy()
    BashPlugin(config).generate_pvp_policy(policy)
    
    print("Policy file created successfully!")

if __name__ == '__main__':
    main()