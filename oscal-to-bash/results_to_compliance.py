"""
This module handles the results to compliance transformation.
"""
import argparse 

from c2p.framework.c2p import C2P
from c2p.framework.models import RawResult

from bash_plugin import BashPluginConfig, BashPlugin



parser = argparse.ArgumentParser()
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

    check_results = open(args.results_file, 'r').read().strip()
    pvp_raw_result = RawResult(data=check_results)
    pvp_result = BashPlugin(config).generate_pvp_result(pvp_raw_result)
    for obs in pvp_result.observations_by_check:
        for sub in obs.subjects:
            print(f'Check: {obs.check_id}, Status: {sub.result.value}')
            
if __name__ == '__main__':
    main()