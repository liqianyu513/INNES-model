import math
import sys
import codecs
from agent.agent_wrapper import AgentWrapper, EnvironmentBounds, Verbosity, ActionTrackingStateAugmentation
import logging
import numpy as np
from ap_env import interaction
from typing import Tuple, Optional, List
from typing_extensions import TypedDict
import progressbar
import abc


class Learner(abc.ABC):

    def new_episode(self) -> None:
        return None

    def end_of_episode(self, i_episode, t) -> None:
        return None

    def end_of_iteration(self, t, done) -> None:
        return None

    @abc.abstractmethod
    def explore(self, wrapped_env: AgentWrapper) -> Tuple[str, interaction.Action, object]:
        """Exploration function.
        Returns (action_type, gym_action, action_metadata) where
        action_metadata is a custom object that gets passed to the on_step callback function"""
        raise NotImplementedError

    @abc.abstractmethod
    def exploit(self, wrapped_env: AgentWrapper, observation) -> Tuple[str, Optional[interaction.Action], object]:
        """Exploit function.
        Returns (action_type, gym_action, action_metadata) where
        action_metadata is a custom object that gets passed to the on_step callback function"""
        raise NotImplementedError

    @abc.abstractmethod
    def on_step(self, wrapped_env: AgentWrapper, observation, reward, done, info, action_metadata) -> None:
        raise NotImplementedError


class RandomPolicy(Learner):
    """A policy that does not learn and only explore"""

    def explore(self, wrapped_env: AgentWrapper) -> Tuple[str, interaction.Action, object]:
        # gym_action = wrapped_env.env.sample_valid_action()
        gym_action = wrapped_env.env.sample_random_action()
        return "explore", gym_action, None

    def exploit(self, wrapped_env: AgentWrapper, observation) -> Tuple[str, Optional[interaction.Action], object]:
        raise NotImplementedError

    def on_step(self, wrapped_env: AgentWrapper, observation, reward, done, info, action_metadata):
        return None


Breakdown = TypedDict('Breakdown', {
    'local': int,
    'remote': int,
    'connect': int
})

Outcomes = TypedDict('Outcomes', {
    'reward': Breakdown,
    'noreward': Breakdown
})

Stats = TypedDict('Stats', {
    'exploit': Outcomes,
    'explore': Outcomes,
    'exploit_deflected_to_explore': int
})

TrainedLearner = TypedDict('TrainedLearner', {
    'all_episodes_rewards': List[List[float]],
    'learner': Learner,
    'trained_on': str,
    'title': str
})


def print_stats(stats):
    """Print learning statistics"""

    def print_breakdown(stats, actiontype: str):
        def ratio(kind: str) -> str:
            x, y = stats[actiontype]['reward'][kind], stats[actiontype]['noreward'][kind]
            sum = x + y
            if sum == 0:
                return 'NaN'
            else:
                return f"{(x / sum):.2f}"

        def print_kind(kind: str):
            print(
                f"    {actiontype}-{kind}: {stats[actiontype]['reward'][kind]}/{stats[actiontype]['noreward'][kind]} "
                f"({ratio(kind)})")

        print_kind('local')
        print_kind('remote')
        print_kind('connect')

    print("  Breakdown [Reward/NoReward (Success rate)]")
    print_breakdown(stats, 'explore')
    print_breakdown(stats, 'exploit')
    print(f"  exploit deflected to exploration: {stats['exploit_deflected_to_explore']}")


def epsilon_greedy_search(
        gym_env: interaction.AutoPentestEnv,
        environment_properties: EnvironmentBounds,
        learner: Learner,
        title: str,
        episode_count: int,
        iteration_count: int,
        epsilon: float,
        epsilon_minimum=0.0,
        epsilon_multdecay: Optional[float] = None,
        epsilon_exponential_decay: Optional[int] = None,
        render=True,
        verbosity: Verbosity = Verbosity.Normal
) -> TrainedLearner:
    print(f"###### {title}\n"
          f"Learning with: episode_count={episode_count},"
          f"iteration_count={iteration_count},"
          f"ϵ={epsilon},"
          f'ϵ_min={epsilon_minimum}, '
          + (f"ϵ_multdecay={epsilon_multdecay}," if epsilon_multdecay else '')
          + (f"ϵ_expdecay={epsilon_exponential_decay}," if epsilon_exponential_decay else ''))

    initial_epsilon = epsilon

    all_episodes_rewards = []

    wrapped_env = AgentWrapper(gym_env,
                               ActionTrackingStateAugmentation(environment_properties))
    steps_done = 0

    fname0 = "E:/AP/results"
    fnameadd = "/" + "network4" + ".txt"
    fname = fname0 + fnameadd
    for i_episode in range(1, episode_count + 1):

        print(f"  ## Episode: {i_episode}/{episode_count} '{title}' "
              )

        observation = wrapped_env.reset()
        total_reward = 0.0
        all_rewards = []
        learner.new_episode()  # 新的周期开始

        stats = Stats(exploit=Outcomes(reward=Breakdown(local=0, remote=0, connect=0),
                                       noreward=Breakdown(local=0, remote=0, connect=0)),
                      explore=Outcomes(reward=Breakdown(local=0, remote=0, connect=0),
                                       noreward=Breakdown(local=0, remote=0, connect=0)),
                      exploit_deflected_to_explore=0
                      )

        episode_ended_at = None
        sys.stdout.flush()

        bar = progressbar.ProgressBar(
            widgets=[
                'Episode ',
                f'{i_episode}',
                '|Iteration ',
                progressbar.Counter(),
                '|',
                progressbar.Variable(name='reward', width=6, precision=10),
                '|',
                progressbar.Timer(),
                progressbar.Bar(),
            ],
            redirect_stdout=False)

        for t in bar(range(1, 1 + iteration_count)):

            if epsilon_exponential_decay:
                epsilon = epsilon_minimum + math.exp(-1. * steps_done /
                                                     epsilon_exponential_decay) * (initial_epsilon - epsilon_minimum)

            steps_done += 1

            x = np.random.rand()
            if x <= epsilon:
                action_style, gym_action, action_metadata = learner.explore(wrapped_env)
            else:
                action_style, gym_action, action_metadata = learner.exploit(wrapped_env, observation)
                if not gym_action:
                    stats['exploit_deflected_to_explore'] += 1
                    _, gym_action, action_metadata = learner.explore(wrapped_env)

            logging.debug(f"gym_action={gym_action}, action_metadata={action_metadata}")
            observation, reward, done, info = wrapped_env.step(gym_action)
            action_type = 'exploit' if action_style == 'exploit' else 'explore'
            outcome = 'reward' if reward > 0 else 'noreward'
            if 'local_vulnerability' in gym_action:
                stats[action_type][outcome]['local'] += 1
            elif 'remote_vulnerability' in gym_action:
                stats[action_type][outcome]['remote'] += 1
            else:
                stats[action_type][outcome]['connect'] += 1

            learner.on_step(wrapped_env, observation, reward, done, info, action_metadata)
            assert np.shape(reward) == ()

            if reward < 0:
                reward = 0

            total_reward += reward
            all_rewards.append(reward)
            bar.update(t, reward=total_reward)

            if verbosity == Verbosity.Verbose or (verbosity == Verbosity.Normal and reward > 1):
                sign = ['-', '+'][reward > 0]

                print(f"    {sign} t={t} {action_style} r={reward} cum_reward:{total_reward} "
                      f"a={action_metadata}-{gym_action} "
                      f"creds={len(observation['credential_cache_matrix'])} ")

            learner.end_of_iteration(t, done)

            if done:
                episode_ended_at = t
                bar.finish(dirty=True)
                break

        sys.stdout.flush()

        if episode_ended_at:
            print(f"  Episode {i_episode} ended at t={episode_ended_at} ")
        else:
            print(f"  Episode {i_episode} stopped at t={iteration_count} ")

        print_stats(stats)

        all_episodes_rewards.append(all_rewards)

        length = episode_ended_at if episode_ended_at else iteration_count

        learner.end_of_episode(i_episode=i_episode, t=length)

        if render:
            wrapped_env.render()

        if epsilon_multdecay:
            epsilon = max(epsilon_minimum, epsilon * epsilon_multdecay)

        content = TrainedLearner(
            all_episodes_rewards=all_episodes_rewards,
            learner=learner,
            trained_on=gym_env.name,
            title=''
        )
        f = codecs.open(fname, 'w', 'utf-8')
        f.write(str(content))
        f.close()

    wrapped_env.close()
    print("simulation ended")

    return TrainedLearner(
        all_episodes_rewards=all_episodes_rewards,
        learner=learner,
        trained_on=gym_env.name,
        title=''
    )
