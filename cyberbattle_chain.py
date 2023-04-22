# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""CyberBattle environment based on a simple chain network structure"""

from scenario import chainpattern
from ap_env import interaction


class CyberBattleChain(interaction.AutoPentestEnv):
    """CyberBattle environment based on a simple chain network structure"""

    def __init__(self, size, **kwargs):
        self.size = size
        super().__init__(
            initial_environment=chainpattern.new_environment(size),
            node_count=10,
            **kwargs)

    @ property
    def name(self) -> str:
        return f"CyberBattleChain-{self.size}"
