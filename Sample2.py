
"""A CyberBattle simulation over a randomly generated network"""

from scenario import sample2
from ap_env import interaction

class CyberBattleRandom2(interaction.AutoPentestEnv):
    """A sample CyberBattle environment"""

    def __init__(self, **kwargs):
        super().__init__(initial_environment=sample2.new_environment(),
                         **kwargs)
