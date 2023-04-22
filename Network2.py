from scenario import network2
from ap_env import interaction


class AP_Network2(interaction.AutoPentestEnv):
    def __init__(self, ** kwargs):
        super().__init__(
            # node_count=10,
            initial_environment=network2.new_environment(),
            **kwargs)
