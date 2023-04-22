from scenario import network4
from ap_env import interaction


class AP_Network4(interaction.AutoPentestEnv):
    def __init__(self, ** kwargs):
        super().__init__(
            # node_count=10,
            initial_environment=network4.new_environment(),
            **kwargs)
