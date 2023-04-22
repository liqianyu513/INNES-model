from ap_env.interaction import EnvironmentBounds
from typing import Optional, List
import enum
import numpy as np
from gym import spaces, Wrapper
from numpy import ndarray
import ap_env.interaction as interaction
from networkx import convert_matrix


class StateAugmentation:

    def __init__(self, observation: Optional[interaction.Observation] = None):
        self.observation = observation

    def on_step(self, action: interaction.Action, reward: float, done: bool, observation: interaction.Observation):
        self.observation = observation

    def on_reset(self, observation: interaction.Observation):
        self.observation = observation


class Feature(spaces.MultiDiscrete):

    def __init__(self, env_properties: EnvironmentBounds, nvec):
        self.env_properties = env_properties
        super().__init__(nvec)

    def flat_size(self):
        return np.prod(self.nvec)

    def name(self):
        """Return the name of the feature"""
        p = len(type(Feature(self.env_properties, [])).__name__) + 1
        return type(self).__name__[p:]

    def get(self, a: StateAugmentation, node: Optional[int]) -> np.ndarray:
        """Compute the current value of a feature value at
        the current observation and specific node"""
        raise NotImplementedError


class Feature_node_topology(Feature):
    """Network Topology"""

    def __init__(self, p: EnvironmentBounds):
        self.p = p
        super().__init__(p, [[5] * p.node_count] * p.node_count)

    def get(self, a: StateAugmentation, node) -> np.ndarray:
        topology = convert_matrix.to_numpy_array(a.observation['explored_network'], weight='kind_as_float',
                                                 nodelist=a.observation['discovered_nodes'])
        privilegelevel = a.observation['nodes_privilegelevel']
        for i in range(len(topology)):
            topology[i][i] = privilegelevel[i] * 1.0

        if (self.p.node_count - len(topology)) is not 0:
            add0 = [[0.] * (self.p.node_count - len(topology))] * len(topology)
            add1 = [[0.] * self.p.node_count] * (self.p.node_count - len(topology))
            t0 = np.concatenate((topology, add0), axis=1)
            topology = np.concatenate((t0, add1))
        return topology


class Feature_node_properties(Feature):

    def __init__(self, p: EnvironmentBounds):
        self.p = p
        super().__init__(p, [[2] * p.property_count] * p.node_count)

    def get(self, a: StateAugmentation, node=None) -> ndarray:
        node_prop = a.observation['discovered_nodes_properties']
        find_prop = len(node_prop)
        if (self.p.node_count - find_prop) is not 0:
            add = [[0] * self.p.property_count] * (self.p.node_count - find_prop)
            node_prop = np.concatenate((node_prop, add))
        remapped = np.array((node_prop + 1) / 2, dtype=np.int)
        return remapped


class ConcatFeatures(Feature):
    def __init__(self, p: EnvironmentBounds, feature_selection: List[Feature]):
        self.feature_selection = feature_selection
        self.dim_sizes = np.concatenate([f.nvec for f in feature_selection])
        super().__init__(p, [self.dim_sizes])

    def get(self, a: StateAugmentation, node) -> np.ndarray:
        """Return the feature vector"""
        feature_vector = [f.get(a, node) for f in self.feature_selection]
        return np.concatenate(feature_vector)


class ConcatFeatures0(Feature):

    def __init__(self, p: EnvironmentBounds, feature_selection: List[Feature]):
        self.feature_selection = feature_selection
        self.dim_sizes = np.concatenate([f.nvec for f in feature_selection], axis=1)
        super().__init__(p, self.dim_sizes)

    def get(self, a: StateAugmentation, node) -> np.ndarray:
        """Return the feature vector"""
        feature_vector = [f.get(a, node) for f in self.feature_selection]
        return np.concatenate(feature_vector, axis=1)


class AbstractAction(Feature):  # 抽象动作
    """ - local_attack(vulnid)    (source_node provided)
        - remote_attack(vulnid)   (source_node provided, target_node forgotten)
        - connect(port)           (source_node provided, target_node forgotten, credentials infered from cache)
    """

    def __init__(self, p: EnvironmentBounds):
        self.n_local_actions = p.local_attacks_count
        self.n_remote_actions = p.remote_attacks_count
        self.n_connect_actions = p.port_count
        self.n_node = p.node_count
        self.n_credentials = p.total_credentials
        self.n_actions = self.n_local_actions * p.node_count + self.n_remote_actions * p.node_count * p.node_count + \
                         self.n_connect_actions * p.node_count * p.node_count * p.total_credentials
        super().__init__(p, [self.n_actions])

    def specialize_to_gymaction(self, observation, abstract_action_index: np.int32
                                ) -> Optional[interaction.Action]:

        abstract_action_index_int = int(abstract_action_index)

        if abstract_action_index_int < self.n_node * self.n_local_actions:
            vuln = abstract_action_index_int % self.n_local_actions
            source_node = int(abstract_action_index_int / self.n_local_actions)
            return {'local_vulnerability': np.array([source_node, vuln])}

        abstract_action_index_int -= self.n_node * self.n_local_actions
        if abstract_action_index_int < self.n_node * self.n_node * self.n_remote_actions:
            source_node = int(abstract_action_index_int / (self.n_node * self.n_remote_actions))
            noreason = abstract_action_index_int - source_node * (self.n_node * self.n_remote_actions)
            target = int(noreason / self.n_remote_actions)
            vuln = noreason % self.n_remote_actions

            return {'remote_vulnerability': np.array([source_node, target, vuln])}

        abstract_action_index_int -= self.n_node * self.n_node * self.n_remote_actions
        source_node = int(abstract_action_index_int / (self.n_node * self.n_connect_actions * self.n_credentials))
        noreason = abstract_action_index_int - source_node * (self.n_node * self.n_connect_actions * self.n_credentials)
        target = int(noreason / (self.n_connect_actions * self.n_credentials))
        noreason1 = noreason - target * (self.n_connect_actions * self.n_credentials)
        port = int(noreason1 / self.n_credentials)
        credential = int(noreason1 % self.n_credentials)
        return {'connect': np.array([source_node, target, port, credential], dtype=np.int32)}

    def abstract_from_gymaction(self, gym_action: interaction.Action) -> np.int32:
        if 'local_vulnerability' in gym_action:
            return gym_action['local_vulnerability'][0] * self.n_local_actions + gym_action['local_vulnerability'][1]
        elif 'remote_vulnerability' in gym_action:
            r = gym_action['remote_vulnerability']
            num = r[0] * self.n_node * self.n_remote_actions + r[1] * self.n_remote_actions + r[2]
            return self.n_local_actions * self.n_node + num

        assert 'connect' in gym_action
        c = gym_action['connect']
        num1 = c[0] * self.n_node * self.n_connect_actions * self.n_credentials + \
               c[1] * self.n_connect_actions * self.n_credentials + c[2] * self.n_credentials + c[3]
        a = self.n_local_actions * self.n_node + self.n_remote_actions * self.n_node * self.n_node + num1
        assert a < self.n_actions
        return np.int32(a)


class ActionTrackingStateAugmentation(StateAugmentation):

    def __init__(self, p: EnvironmentBounds, observation: Optional[interaction.Observation] = None):
        self.aa = AbstractAction(p)
        self.success_action_count = np.zeros(shape=(p.node_count, self.aa.n_actions), dtype=np.int32)
        self.failed_action_count = np.zeros(shape=(p.node_count, self.aa.n_actions), dtype=np.int32)
        self.env_properties = p
        super().__init__(observation)

    def on_step(self, action: interaction.Action, reward: float, done: bool, observation: interaction.Observation):
        node = interaction.sourcenode_of_action(action)
        abstract_action = self.aa.abstract_from_gymaction(action)
        if reward > 0:
            self.success_action_count[node, abstract_action] += 1
        else:
            self.failed_action_count[node, abstract_action] += 1
        super().on_step(action, reward, done, observation)

    def on_reset(self, observation: interaction.Observation):
        p = self.env_properties
        self.success_action_count = np.zeros(shape=(p.node_count, self.aa.n_actions), dtype=np.int32)
        self.failed_action_count = np.zeros(shape=(p.node_count, self.aa.n_actions), dtype=np.int32)
        super().on_reset(observation)

class Verbosity(enum.Enum):
    Quiet = 0
    Normal = 1
    Verbose = 2


class AgentWrapper(Wrapper):

    def __init__(self, env: interaction.AutoPentestEnv, state: StateAugmentation):
        super().__init__(env)
        self.state = state

    def step(self, action: interaction.Action):
        observation, reward, done, info = self.env.step(action)
        self.state.on_step(action, reward, done, observation)
        return observation, reward, done, info

    def reset(self):
        observation = self.env.reset()
        self.state.on_reset(observation)
        return observation
