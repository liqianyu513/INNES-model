#!/usr/bin/python3.8
# -*- coding: utf-8 -*-

import torch
import gym
import logging
import sys
import argparse
from agent.agent_wrapper import Verbosity
import agent.agent_dql as dqla
import agent.agent_wrapper as w
import agent.learner as learner
from gym.envs.registration import registry, EnvSpec
from gym.error import Error

from ap_env.interaction import AttackerGoal
from scenario import ToyCtf
from scenario import chainpattern
from scenario import network1, network2, network3, network4, sample1, sample2
from simulation import model


def register(id: str, ap_env_identifiers: model.Identifiers, **kwargs):
    if id in registry.env_specs:
        raise Error('Cannot re-register id: {}'.format(id))
    spec = EnvSpec(id, **kwargs)
    # Map from port number to port names : List[model.PortName]
    spec.ports = ap_env_identifiers.ports
    # Array of all possible node properties (not necessarily all used in the network) : List[model.PropertyName]
    spec.properties = ap_env_identifiers.properties
    # Array defining an index for every possible local vulnerability name : List[model.VulnerabilityID]
    spec.local_vulnerabilities = ap_env_identifiers.local_vulnerabilities
    # Array defining an index for every possible remote  vulnerability name : List[model.VulnerabilityID]
    spec.remote_vulnerabilities = ap_env_identifiers.remote_vulnerabilities

    registry.env_specs[id] = spec


#########################   ----ToyCTF----   ###############################################
# if 'ToyCtf-v0' in registry.env_specs:
#     del registry.env_specs['ToyCtf-v0']
#
# register(
#     id='ToyCtf-v0',
#     ap_env_identifiers=ToyCtf.ENV_IDENTIFIERS,
#     entry_point='toy_ctf:AP_ToyCtf',
#     kwargs={'attacker_goal': AttackerGoal(reward=889)}
# )
#
#
# parser = argparse.ArgumentParser(description='Run simulation with DQL baseline agent.')
# parser.add_argument('--rewardplot_with', default=80, type=int,
#                     help='width of the reward plot (values are averaged across iterations to fit in the desired width)')
#
# args = parser.parse_args()
#
# logging.basicConfig(stream=sys.stdout, level=logging.ERROR, format="%(levelname)s: %(message)s")
#
# print(f"torch cuda available={torch.cuda.is_available()}")
#
# toy_ctf = gym.make('ToyCtf-v0')
#
# ep = w.EnvironmentBounds.of_identifiers(
#     total_credentials=5,
#     node_count=10,
#     identifiers=toy_ctf.identifiers
# )
# #########################   ----chainpattern----   ###############################################
#
# if 'CyberBattleChain-v0' in registry.env_specs:
#     del registry.env_specs['CyberBattleChain-v0']
#
# register(
#     id='CyberBattleChain-v0',
#     ap_env_identifiers=chainpattern.ENV_IDENTIFIERS,
#     entry_point='cyberbattle_chain:CyberBattleChain',
#     kwargs={'size': 4,
#             'attacker_goal': AttackerGoal(reward=2180)
#             }
# )
#
# parser = argparse.ArgumentParser(description='Run simulation with DQL baseline agent.')
# parser.add_argument('--rewardplot_with', default=80, type=int,
#                     help='width of the reward plot (values are averaged across iterations to fit in the desired width)')
#
# args = parser.parse_args()
# logging.basicConfig(stream=sys.stdout, level=logging.ERROR, format="%(levelname)s: %(message)s")
#
# print(f"torch cuda available={torch.cuda.is_available()}")
#
# cyberbattlechain = gym.make('CyberBattleChain-v0')
#
# ep = w.EnvironmentBounds.of_identifiers(
#     total_credentials=5,
#     node_count=10,
#     identifiers=cyberbattlechain.identifiers
# )
# #########################   ----sample1----   ###############################################
# if 'sample1-v0' in registry.env_specs:
#     del registry.env_specs['sample1-v0']
#
# register(
#     id='sample1-v0',
#     ap_env_identifiers=model.SAMPLE_IDENTIFIERS1,
#     entry_point='Sample1:CyberBattleRandom1',
#     kwargs={'attacker_goal': AttackerGoal(reward=1571)},
# )
#
# parser = argparse.ArgumentParser(description='Run simulation with DQL baseline agent.')
# parser.add_argument('--rewardplot_with', default=80, type=int,
#                     help='width of the reward plot (values are averaged across iterations to fit in the desired width)')
#
# args = parser.parse_args()
# logging.basicConfig(stream=sys.stdout, level=logging.ERROR, format="%(levelname)s: %(message)s")
#
# print(f"torch cuda available={torch.cuda.is_available()}")
#
# S1 = gym.make('sample1-v0')
#
# ep = w.EnvironmentBounds.of_identifiers(
#     total_credentials=5,
#     node_count=10,
#     identifiers=S1.identifiers
# )
# #########################   ----sample2----   ###############################################
# if 'sample2-v0' in registry.env_specs:
#     del registry.env_specs['sample2-v0']
#
# register(
#     id='sample2-v0',
#     ap_env_identifiers=model.SAMPLE_IDENTIFIERS2,
#     entry_point='Sample2:CyberBattleRandom2',
#     kwargs={'attacker_goal': AttackerGoal(reward=1133)},
# )
#
# parser = argparse.ArgumentParser(description='Run simulation with DQL baseline agent.')
# parser.add_argument('--rewardplot_with', default=80, type=int,
#                     help='width of the reward plot (values are averaged across iterations to fit in the desired width)')
#
# args = parser.parse_args()
# logging.basicConfig(stream=sys.stdout, level=logging.ERROR, format="%(levelname)s: %(message)s")
#
# print(f"torch cuda available={torch.cuda.is_available()}")
#
# S2 = gym.make('sample2-v0')
#
# ep = w.EnvironmentBounds.of_identifiers(
#     total_credentials=5,
#     node_count=10,
#     identifiers=S2.identifiers
# )
#
# #########################   ----network1----   ###############################################
if 'Network-v0' in registry.env_specs:
    del registry.env_specs['Network-v0']

register(
    id='Network-v0',
    ap_env_identifiers=network1.ENV_IDENTIFIERS,
    entry_point='Network1:AP_Network1',
    kwargs={'attacker_goal': AttackerGoal(reward=648)}
)

parser = argparse.ArgumentParser(description='Run simulation with DQL baseline agent.')
parser.add_argument('--rewardplot_with', default=80, type=int,
                    help='width of the reward plot (values are averaged across iterations to fit in the desired width)')

args = parser.parse_args()

logging.basicConfig(stream=sys.stdout, level=logging.ERROR, format="%(levelname)s: %(message)s")

print(f"torch cuda available={torch.cuda.is_available()}")

network1 = gym.make('Network-v0')

ep = w.EnvironmentBounds.of_identifiers(
    total_credentials=5,
    node_count=10,
    identifiers=network1.identifiers
)
# #########################   ----network2----   ###############################################
# if 'Network-v0' in registry.env_specs:
#     del registry.env_specs['Network-v0']
#
# register(
#     id='Network-v0',
#     ap_env_identifiers=network2.ENV_IDENTIFIERS,
#     entry_point='Network2:AP_Network2',
#     kwargs={'attacker_goal': AttackerGoal(reward=823)}
# )
#
# parser = argparse.ArgumentParser(description='Run simulation with DQL baseline agent.')
# parser.add_argument('--rewardplot_with', default=80, type=int,
#                     help='width of the reward plot (values are averaged across iterations to fit in the desired width)')
#
# args = parser.parse_args()
#
# logging.basicConfig(stream=sys.stdout, level=logging.ERROR, format="%(levelname)s: %(message)s")
#
# print(f"torch cuda available={torch.cuda.is_available()}")
#
# network2 = gym.make('Network-v0')
#
# ep = w.EnvironmentBounds.of_identifiers(
#     total_credentials=5,
#     node_count=10,
#     identifiers=network2.identifiers
# )
#########################   ----network3----   ###############################################
# if 'Network-v0' in registry.env_specs:
#     del registry.env_specs['Network-v0']
#
# register(
#     id='Network-v0',
#     ap_env_identifiers=network3.ENV_IDENTIFIERS,
#     entry_point='Network3:AP_Network3',
#     kwargs={'attacker_goal': AttackerGoal(reward=1206)}
# )
#
# parser = argparse.ArgumentParser(description='Run simulation with DQL baseline agent.')
# parser.add_argument('--rewardplot_with', default=80, type=int,
#                     help='width of the reward plot (values are averaged across iterations to fit in the desired width)')
#
# args = parser.parse_args()
#
# logging.basicConfig(stream=sys.stdout, level=logging.ERROR, format="%(levelname)s: %(message)s")
#
# print(f"torch cuda available={torch.cuda.is_available()}")
#
# network3 = gym.make('Network-v0')
#
# ep = w.EnvironmentBounds.of_identifiers(
#     total_credentials=5,
#     node_count=10,
#     identifiers=network3.identifiers
# )
#########################   ----network4----   ###############################################
# if 'Network-v0' in registry.env_specs:
#     del registry.env_specs['Network-v0']
#
# register(
#     id='Network-v0',
#     ap_env_identifiers=network4.ENV_IDENTIFIERS,
#     entry_point='Network4:AP_Network4',
#     kwargs={'attacker_goal': AttackerGoal(reward=1433)}
# )
#
# parser = argparse.ArgumentParser(description='Run simulation with DQL baseline agent.')
# parser.add_argument('--rewardplot_with', default=80, type=int,
#                     help='width of the reward plot (values are averaged across iterations to fit in the desired width)')
#
# args = parser.parse_args()
#
# logging.basicConfig(stream=sys.stdout, level=logging.ERROR, format="%(levelname)s: %(message)s")
#
# print(f"torch cuda available={torch.cuda.is_available()}")
#
# network4 = gym.make('Network-v0')
#
# ep = w.EnvironmentBounds.of_identifiers(
#     total_credentials=5,
#     node_count=10,
#     identifiers=network4.identifiers
# )
###############################################################################################################
all_runs = []
saved_model = dqla.DeepQLearnerPolicy(
    ep=ep,
    gamma=0.99,
    replay_memory_size=1000,
    target_update=10,
    batch_size=512,
    learning_rate=0.01)

dqn_learning_run = learner.epsilon_greedy_search(
    gym_env=network1,
    environment_properties=ep,
    learner=saved_model,  # torch default is 1e-2
    episode_count=100,
    iteration_count=20000,
    epsilon=0.9,
    render=False,
    epsilon_multdecay=0.75,  # 0.999,0.10
    epsilon_exponential_decay=5000,  # 10000
    epsilon_minimum=0.1,
    verbosity=Verbosity.Quiet,  # Quiet = 0  Normal = 1  Verbose = 2
    title="DQL"
)
all_runs.append(dqn_learning_run)
##############################################################################################################
# Run random search
# random_run = learner.epsilon_greedy_search(
#     network1,
#     ep,
#     learner=learner.RandomPolicy(),
#     episode_count=1000,
#     iteration_count=20000,
#     epsilon=1.0,  # purely random
#     render=False,
#     verbosity=Verbosity.Quiet,
#     title="Random search"
# )
# all_runs.append(random_run)

# colors = [asciichartpy.red, asciichartpy.green, asciichartpy.yellow, asciichartpy.blue]
#
# print("Episode duration -- DQN=Red, Random=Green")
# print(asciichartpy.plot(p.episodes_lengths_for_all_runs(all_runs), {'height': 30, 'colors': colors}))
#
# print("Cumulative rewards -- DQN=Red, Random=Green")
# c = p.averaged_cummulative_rewards(all_runs, args.rewardplot_with)
# print(asciichartpy.plot(c, {'height': 10, 'colors': colors}))

