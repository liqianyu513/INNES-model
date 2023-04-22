from numpy import ndarray
import ap_env.interaction as interaction
import numpy as np
from typing import List, NamedTuple, Optional, Tuple, Union
import random
from torch import Tensor
import torch.nn.functional as F
import torch.optim as optim
import torch.nn as nn
import torch
import torch.cuda
from ap_env.interaction import EnvironmentBounds
import agent.agent_wrapper as w
from agent.learner import Learner

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
torch.backends.cudnn.enabled = False


class StateActionModel:
    """ Define an abstraction of the state and action space  """

    def __init__(self, ep: EnvironmentBounds):
        self.ep = ep
        self.global_features = w.ConcatFeatures(ep, [
            w.Feature_node_topology(ep)])
        self.node_specific_features = w.ConcatFeatures(ep, [
            w.Feature_node_properties(ep)])
        self.state_space = w.ConcatFeatures0(ep, self.global_features.feature_selection +
                                             self.node_specific_features.feature_selection)
        self.action_space = w.AbstractAction(ep)

    def implement_action(
            self,
            wrapped_env: w.AgentWrapper,
            abstract_action: np.int32) -> Tuple[str, Optional[interaction.Action]]:
        observation = wrapped_env.state.observation
        gym_action = self.action_space.specialize_to_gymaction(
            observation, np.int32(abstract_action))

        if not gym_action:
            return "exploit[undefined]->explore", None

        elif wrapped_env.env.is_action_valid(gym_action, observation['action_mask']):
            return "exploit", gym_action
        else:
            return "exploit[invalid]->explore", None


# Deep Q-learning


class Transition(NamedTuple):
    """One taken transition and its outcome"""
    state: Union[Tuple[Tensor], List[Tensor]]
    action: Union[Tuple[Tensor], List[Tensor]]
    next_state: Union[Tuple[Tensor], List[Tensor]]
    reward: Union[Tuple[Tensor], List[Tensor]]


class ReplayMemory(object):
    """Transition replay memory"""

    def __init__(self, capacity):
        self.capacity = capacity
        self.memory = []
        self.position = 0

    def push(self, *args):
        """Saves a transition."""
        if len(self.memory) < self.capacity:
            self.memory.append(None)
        self.memory[self.position] = Transition(*args)
        self.position = (self.position + 1) % self.capacity

    def sample(self, batch_size):
        return random.sample(self.memory, batch_size)

    def __len__(self):
        return len(self.memory)


def conv2d_size_out(size, kernel_size=5, stride=2):
    return (size - (kernel_size - 1) - 1) // stride + 1


class DQN(nn.Module):
    """The Deep Neural Network used to estimate the Q function"""

    def __init__(self, ep: EnvironmentBounds):
        super(DQN, self).__init__()

        model = StateActionModel(ep)
        self.width = len(model.state_space[0])
        self.height = len(model.state_space)
        output_size = model.action_space.flat_size()

        linear_input_size = self.width * self.height
        self.hidden_layer1 = nn.Linear(linear_input_size, 1024)
        self.hidden_layer2 = nn.Linear(1024, 512)
        self.hidden_layer3 = nn.Linear(512, 128)
        self.head = nn.Linear(128, output_size)

    # Called with either one element to determine next action, or a batch
    # during optimization. Returns tensor([[left0exp,right0exp]...]).
    def forward(self, x):
        x = x.reshape([-1, self.height * self.width])
        x = F.relu(self.hidden_layer1(x))
        x = F.relu(self.hidden_layer2(x))
        x = F.relu(self.hidden_layer3(x))
        return self.head(x.view(x.size(0), -1))


def random_argmax(array):
    max_value = np.max(array)
    max_index = np.where(array == max_value)[0]

    if max_index.shape[0] > 1:
        max_index = int(np.random.choice(max_index, size=1))
    else:
        max_index = int(max_index)

    return max_value, max_index


class ChosenActionMetadata(NamedTuple):
    abstract_action: np.int32
    actor_features: ndarray
    actor_state: ndarray

    def __repr__(self) -> str:
        return f"[abstract_action={self.abstract_action}, state={self.actor_state}]"


class DeepQLearnerPolicy(Learner):
    def __init__(self,
                 ep: EnvironmentBounds,
                 gamma: float,
                 replay_memory_size: int,
                 target_update: int,
                 batch_size: int,
                 learning_rate: float
                 ):

        self.stateaction_model = StateActionModel(ep)
        self.batch_size = batch_size
        self.gamma = gamma
        self.learning_rate = learning_rate

        self.policy_net = DQN(ep).to(device)
        self.target_net = DQN(ep).to(device)
        self.target_net.load_state_dict(self.policy_net.state_dict())

        self.target_net.eval()
        self.target_update = target_update

        self.optimizer = optim.Adam(self.policy_net.parameters(), lr=learning_rate, betas=(0.9, 0.99))
        self.memory = ReplayMemory(replay_memory_size)

        self.state_history = []
        self.action_list = []

    def parameters_as_string(self):
        return f'γ={self.gamma}, lr={self.learning_rate}, replaymemory={self.memory.capacity},\n' \
               f'batch={self.batch_size}, target_update={self.target_update}'

    def all_parameters_as_string(self) -> str:
        model = self.stateaction_model
        return f'{self.parameters_as_string()}\n' \
               f'dimension={model.state_space.flat_size()}x{model.action_space.flat_size()}, ' \
               f'Q={[f.name() for f in model.state_space.feature_selection]} ' \
               f"-> 'abstract_action'"

    def optimize_model(self, norm_clipping=False):
        if len(self.memory) < self.batch_size:
            return

        transitions = self.memory.sample(self.batch_size)
        batch = Transition(*zip(*transitions))
        non_final_mask = torch.tensor(tuple(map((lambda s: s is not None), batch.next_state)),
                                      device=device, dtype=torch.bool)
        non_final_next_states = torch.cat([s for s in batch.next_state
                                           if s is not None])

        state_batch = torch.cat(batch.state)
        action_batch = torch.cat(batch.action)
        reward_batch = torch.cat(batch.reward)

        output = self.policy_net(state_batch)
        state_action_values = output.gather(1, action_batch)
        next_state_values = torch.zeros(len(transitions), device=device)
        next_state_values[non_final_mask] = self.target_net(non_final_next_states).max(1)[0].detach()

        # Compute the expected Q values
        expected_state_action_values = (next_state_values * self.gamma) + reward_batch

        # Compute Huber loss
        loss = F.smooth_l1_loss(state_action_values, expected_state_action_values.unsqueeze(1))

        self.optimizer.zero_grad()
        loss.backward()

        # Gradient clipping
        if norm_clipping:
            torch.nn.utils.clip_grad_norm_(self.policy_net.parameters(), 1.0)
        else:
            for param in self.policy_net.parameters():
                param.grad.data.clamp_(-1, 1)
        self.optimizer.step()

    def get_actor_state_vector(self, global_state: ndarray, actor_features: ndarray) -> ndarray:
        return np.concatenate((np.array(global_state, dtype=np.float32),
                               np.array(actor_features, dtype=np.float32)), axis=1)

    def update_q_function(self,
                          reward: float,
                          actor_state: ndarray,
                          abstract_action: np.int32,
                          next_actor_state: Optional[ndarray]):
        # store the transition in memory
        reward_tensor = torch.tensor([reward], device=device, dtype=torch.float)
        action_tensor = torch.tensor([[np.long(abstract_action)]], device=device, dtype=torch.long)
        current_state_tensor = torch.as_tensor(actor_state, dtype=torch.float, device=device).unsqueeze(0)
        if next_actor_state is None:
            next_state_tensor = None
        else:
            next_state_tensor = torch.as_tensor(next_actor_state, dtype=torch.float, device=device).unsqueeze(0)
        self.memory.push(current_state_tensor, action_tensor, next_state_tensor, reward_tensor)

        # optimize the target network
        self.optimize_model()

    def on_step(self, wrapped_env: w.AgentWrapper,
                observation, reward: float, done: bool, info, action_metadata):
        agent_state = wrapped_env.state
        if done:
            self.update_q_function(reward,
                                   actor_state=action_metadata.actor_state,
                                   abstract_action=action_metadata.abstract_action,
                                   next_actor_state=None)
        else:
            next_global_state = self.stateaction_model.global_features.get(agent_state, node=None)
            next_actor_features = self.stateaction_model.node_specific_features.get(
                agent_state, node=None)
            next_actor_state = self.get_actor_state_vector(next_global_state, next_actor_features)
            self.update_q_function(reward,
                                   actor_state=action_metadata.actor_state,
                                   abstract_action=action_metadata.abstract_action,
                                   next_actor_state=next_actor_state)

    def end_of_episode(self, i_episode, t):
        # Update the target network, copying all weights and biases in DQN
        if i_episode % self.target_update == 0:
            self.target_net.load_state_dict(self.policy_net.state_dict())

    def lookup_dqn(self, states_to_consider, wrapped_env: w.AgentWrapper) -> Tuple[List[np.int32], List[np.int32]]:
        with torch.no_grad():
            state_batch = torch.tensor(states_to_consider).to(device)

            _, valid_action = wrapped_env.env.compute_action_mask()
            dnn1 = self.policy_net(state_batch)
            dnn = [dnn1[0][i].tolist() for i in valid_action]
        return valid_action, dnn

    def metadata_from_gymaction(self, wrapped_env, gym_action):
        current_global_state = self.stateaction_model.global_features.get(wrapped_env.state, node=None)
        actor_features = self.stateaction_model.node_specific_features.get(wrapped_env.state, node=None)
        abstract_action = self.stateaction_model.action_space.abstract_from_gymaction(gym_action)
        return ChosenActionMetadata(
            abstract_action=abstract_action,
            actor_features=actor_features,
            actor_state=self.get_actor_state_vector(current_global_state, actor_features))

    def explore(self, wrapped_env: w.AgentWrapper
                ) -> Tuple[str, interaction.Action, object]:
        """Random exploration"""
        # gym_action = wrapped_env.env.sample_valid_action(kinds=[0, 1, 2])
        gym_action = wrapped_env.env.sample_random_action()
        metadata = self.metadata_from_gymaction(wrapped_env, gym_action)
        return "explore", gym_action, metadata

    def try_exploit_at_actor_states(
            self,
            wrapped_env,
            current_global_state,
            actor_features,
            abstract_action):

        actor_state = self.get_actor_state_vector(current_global_state, actor_features)

        action_style, gym_action = self.stateaction_model.implement_action(
            wrapped_env, abstract_action)
        if gym_action:
            return action_style, gym_action, ChosenActionMetadata(
                abstract_action=abstract_action,
                actor_features=actor_features,
                actor_state=actor_state)
        else:
            return "exploit[undefined]->explore", None, None

    def exploit(self,
                wrapped_env,
                observation
                ) -> Tuple[str, Optional[interaction.Action], object]:
        current_global_state = self.stateaction_model.global_features.get(wrapped_env.state, node=None)
        actor_features = self.stateaction_model.node_specific_features.get(wrapped_env.state, node=None)
        actor_state_vector = self.get_actor_state_vector(current_global_state, actor_features)
        if self.state_history == [] or (self.state_history[-1] == actor_state_vector).all() != True:
            self.state_history = []
            self.state_history.append(actor_state_vector)
            remaining_action_lookups, remaining_expectedq_lookups = self.lookup_dqn(actor_state_vector, wrapped_env)
            remaining_candidate_indices = list(range(len(remaining_action_lookups)))
            while remaining_candidate_indices:
                _, remaining_candidate_index = random_argmax(remaining_expectedq_lookups)
                abstract_action = remaining_action_lookups[remaining_candidate_index]
                action_style, gym_action, metadata = self.try_exploit_at_actor_states(
                    wrapped_env,
                    current_global_state,
                    actor_features,
                    abstract_action)
                remaining_candidate_indices.pop(remaining_candidate_index)
                remaining_expectedq_lookups.pop(remaining_candidate_index)
                remaining_action_lookups.pop(remaining_candidate_index)
                if gym_action:
                    self.action_list = remaining_action_lookups
                    return action_style, gym_action, metadata
        else:
            remaining_action_lookups, remaining_expectedq_lookups = self.lookup_dqn(actor_state_vector, wrapped_env)
            expectedq = []
            for i in self.action_list:
                for j in range(len(remaining_action_lookups)):
                    if i == remaining_action_lookups[j]:
                        expectedq.append(remaining_expectedq_lookups[j])
                        break
            remaining_action_lookups = self.action_list
            remaining_expectedq_lookups = expectedq
            remaining_candidate_indices = list(range(len(remaining_action_lookups)))
            while remaining_candidate_indices:
                _, remaining_candidate_index = random_argmax(remaining_expectedq_lookups)
                abstract_action = remaining_action_lookups[remaining_candidate_index]
                action_style, gym_action, metadata = self.try_exploit_at_actor_states(
                    wrapped_env,
                    current_global_state,
                    actor_features,
                    abstract_action)
                remaining_candidate_indices.pop(remaining_candidate_index)
                remaining_expectedq_lookups.pop(remaining_candidate_index)
                remaining_action_lookups.pop(remaining_candidate_index)
                if gym_action:
                    return action_style, gym_action, metadata
        ######################################################################################
        # while remaining_candidate_indices:
        #     _, remaining_candidate_index = random_argmax(remaining_expectedq_lookups)
        #     actor_index = remaining_candidate_indices[remaining_candidate_index]
        #     abstract_action = remaining_action_lookups[remaining_candidate_index]
        #
        #     # actor_features = unique_active_actors_features[actor_index]
        #
        #     action_style, gym_action, metadata = self.try_exploit_at_actor_states(
        #         wrapped_env,
        #         current_global_state,
        #         actor_features,
        #         abstract_action)
        #
        #     if gym_action:
        #         return action_style, gym_action, metadata
        #
        #     remaining_candidate_indices.pop(remaining_candidate_index)
        #     remaining_expectedq_lookups.pop(remaining_candidate_index)
        #     remaining_action_lookups.pop(remaining_candidate_index)
        return "exploit[undefined]->explore", None, None

