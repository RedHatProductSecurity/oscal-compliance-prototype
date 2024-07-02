"""
This module handles the results to compliance transformation.
"""
import argparse 

from c2p.framework.c2p import C2P
from c2p.framework.models import RawResult
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
    '-r',
    '--results-file',
    type=str,
    default='./sshd-check.results',
    help=f'Path to output results file.',
    required=False,
)

def main():
    """
    Executes the results to compliance command.
    """
    args = parser.parse_args()
    config = BashPluginConfig()

    c2p_config = C2PConfig()
    c2p_config.compliance = ComplianceOscal()
    c2p_config.compliance.component_definition = args.component_definition
    c2p_config.pvp_name = 'BashExample'
    c2p_config.result_title = 'Bash Example Assessment Results'
    c2p_config.result_description = 'OSCAL Assessment Results from Bash Example'

    c2p = C2P(c2p_config)

    check_results = open(args.results_file, 'r').read().strip()
    pvp_raw_result = RawResult(data=check_results)
    pvp_result = BashPlugin(config).generate_pvp_result(pvp_raw_result)
    c2p.set_pvp_result(pvp_result)
    oscal_assessment_results = c2p.result_to_oscal()

    print(oscal_assessment_results.oscal_serialize_json(pretty=True))
            
if __name__ == '__main__':
    main()