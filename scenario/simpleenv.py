# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""A simple test sandbox to play with creation of simulation environments"""
import networkx as nx
import yaml
from networkx import convert_matrix
from simulation import model, model_test, actions_test


def main() -> None:
# def new_environment():
    """Simple environment sandbox"""

    # Create a toy graph
    # graph = nx.DiGraph()
    # graph.add_edges_from([('a', 'c'), ('b', 'd')])
    # print("EEEEEEEEEEEEEEEE")
    # print(convert_matrix.to_pandas_adjacency(graph))
    # print('EEEEEEEEEEEEEEEEEEEEE')

    # create a random graph
    graph = nx.cubical_graph()
    vulnerabilities = actions_test.SAMPLE_VULNERABILITIES
    graph = model.assign_random_labels(graph, vulnerabilities)

    # for node in list(graph.nodes):
    #     print(graph.nodes[node]

    model.sample_network(graph)


    model.setup_yaml_serializer()
    # identifiers = model.SAMPLE_IDENTIFIERS

    # Define an environment from this graph
    env = model.Environment(
        network=graph,
        vulnerability_library=vulnerabilities,
        # identifiers=actions_test.ENV_IDENTIFIERS
        identifiers=model.SAMPLE_IDENTIFIERS
    )
    #
    print(convert_matrix.to_pandas_adjacency(graph))
    model_test.check_reserializing(env)

    model_test.check_reserializing(vulnerabilities)

    # Save the environment to file as Yaml
    with open('./simpleenv.yaml', 'w') as file:
        yaml.dump(env, file)
    # model.sample_network()
    # print(yaml.dump(env))
    # return env


if __name__ == '__main__':
    main()
