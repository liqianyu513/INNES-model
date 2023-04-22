from scenario import network3
from ap_env import interaction


class AP_Network3(interaction.AutoPentestEnv):
    def __init__(self, ** kwargs):
        super().__init__(
            # node_count=10,
            initial_environment=network3.new_environment(),
            **kwargs)
