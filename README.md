# INNES-model
Based on the CyberbattleSim framework, we design the new penetration testing model INNES and abstract the scenarios network1-network4 from the real network environment.


We propose the INNES (INtelligent peNEtration teSting) model based on deep reinforcement learning (DRL). 


First, the model characterizes the key elements of PT more reasonably based on the Markov decision process (MDP), fully considering
the commonality of the PT process in different scenarios to improve its applicability. 


Second, the DQN valid algorithm is designed to constrain the agent’s action space, to improve the agent’s decision-making accuracy, 
and avoid invalid exploration, according to the feature that enables the effective action space to gradually increase during the PT process.
