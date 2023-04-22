from scenario import network1
from ap_env import interaction


class AP_Network1(interaction.AutoPentestEnv):
    def __init__(self, **kwargs):
        super().__init__(
            node_count=10,
            initial_environment=network1.new_environment(),
            **kwargs)
