"""
Converts OSCAL component definition to bash script config.
"""

import argparse
from typing import List
from pathlib import Path

from trestle.oscal.component import ComponentDefinition


OUTPUT_POLICY_FILE = './sshd-check.config'
COMPONENT_DEFINITION_FILE = './component-definition.json'


def generate_policy_file(output_file: str, params: List) -> Path:
    """
    Create the policy config file.
    """
    with open(output_file, 'w') as f:
        for param in params:
            f.write(f"{param.param_id}={param.values[0]}\n")


def load_component_definition(path: str) -> ComponentDefinition:
    """
    Load the component definition JSON file.
    """
    try:
        return ComponentDefinition.oscal_read(Path(path))

    except Exception as ex:
        print(f'Failed to load component definition: {str(ex)}')


def list_set_parameters(component_definition: ComponentDefinition) -> List:
    """
    Extract the set parameters from the component definition.
    """
    set_params = []
    for component in component_definition.components:
        if implementations := component.control_implementations:
            for implementation in implementations:
                for param in implementation.set_parameters:
                    set_params.append(param)

    return set_params


def main():
    parser = argparse.ArgumentParser(prog='OSCAL2Bash')
    parser.add_argument(
        '-c',
        '--component-definition',
        default=COMPONENT_DEFINITION_FILE
    ) 
    parser.add_argument(
        '-o',
        '--output-file',
        default=OUTPUT_POLICY_FILE
    ) 

    args = parser.parse_args()
    component_definition = load_component_definition(args.component_definition)
    params = list_set_parameters(component_definition)
    output_file = generate_policy_file(args.output_file, params)


if __name__ == '__main__':
    main()
