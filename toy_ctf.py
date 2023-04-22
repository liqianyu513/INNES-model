# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from scenario import ToyCtf
from ap_env import interaction


class AP_ToyCtf(interaction.AutoPentestEnv):
    def __init__(self, ** kwargs):
        super().__init__(
            node_count=10,
            initial_environment=ToyCtf.new_environment(),
            **kwargs)
