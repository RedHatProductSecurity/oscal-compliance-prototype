"""
C2P Bash Plugin Example module.
"""
from typing import Optional, List

import json
from pydantic import Field

from c2p.common.logging import getLogger
from c2p.common.utils import get_datetime
from c2p.framework.plugin_spec import PluginSpec, PluginConfig
from c2p.framework.models import (
    Policy,
    Parameter,
    RawResult,
    PVPResult,
)
from c2p.framework.models.pvp_result import (
    Link,
    ObservationByCheck,
    PVPResult,
    ResultEnum,
    Subject,
)

logger = getLogger(__name__)

status_dictionary = {
    'pass': ResultEnum.Pass,
    'fail': ResultEnum.Failure,
    'warn': ResultEnum.Failure,
    'error': ResultEnum.Error,
}

class BashPluginConfig(PluginConfig):
    output_file: str = Field(
        default='sshd-check.config',
        title='Path to the generated config file.  (default: ./sshd-check.config)'
    )

class BashPlugin(PluginSpec):
    def __init__(self, config: Optional[BashPluginConfig] = None) -> None:
        super().__init__()
        self.config = config

    def generate_pvp_policy(self, policy: Policy):
        """
        Generate the policy file used by the bash script.
        """
        parameters: List[Parameter] = policy.parameters

        with open(self.config.output_file, 'w') as f:
            for param in parameters:
                key = param.id
                value = json.loads(param.value)['default']
                f.write(f"{key}={value}\n")

    def generate_pvp_result(self, raw_result: RawResult) -> PVPResult:
        pvp_result: PVPResult = PVPResult()
        observations: List[ObservationByCheck] = []
        results = raw_result.data.splitlines()

        reasons = {
            'pass': 'sshd_config contains correct setting',
            'fail': 'sshd_config contains incorrect setting'
        }
        for result in results:
            check_id, status = result.split('=')
            timestamp = get_datetime()
            observation = ObservationByCheck(
                check_id=check_id,
                methods=["AUTOMATED"],
                collected=timestamp,
            )

            subject = Subject(
                title=f'Bash Example Check: {check_id}',
                type='sshd_config',
                result=status_dictionary[status] if status in status_dictionary else ResultEnum.Error,
                resource_id=check_id,
                evaluated_on=timestamp,
                reason=f'Result status was {status}',
            ) 
            observation.subjects = [subject]
            observations.append(observation)

        pvp_result.observations_by_check = observations
        return pvp_result
