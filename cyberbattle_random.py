# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""A CyberBattle simulation over a randomly generated network"""

from simulation import generate_network
from ap_env import interaction


class CyberBattleRandom(interaction.AutoPentestEnv):
    """A sample CyberBattle environment"""

    def __init__(self):
        super().__init__(initial_environment=generate_network.new_environment())
