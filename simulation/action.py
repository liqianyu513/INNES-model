from dataclasses import dataclass
import dataclasses
from datetime import time
import boolean
from collections import OrderedDict
import logging
from enum import Enum
from typing import Iterator, List, NamedTuple, Optional, Set, Tuple, Dict, cast
from typing_extensions import TypedDict
from simulation.model import PrivilegeLevel, PropertyName, VulnerabilityID, VulnerabilityType
import simulation.model as model


logger = logging.getLogger(__name__)
Reward = float

DiscoveredNodeInfo = TypedDict('DiscoveredNodeInfo', {
    'id': model.NodeID,
    'status': str
})


class Penalty:
    """Penalties (=negative reward) returned for some actions taken in the simulation 缩小十倍"""
    # penalty for generic suspiciousness
    SUPSPICIOUSNESS = -5

    # penalty for attempting a connection to a port that was not open
    SCANNING_UNOPEN_PORT = -10

    # penalty for repeating the same exploit attempt
    REPEAT = -1

    LOCAL_EXPLOIT_FAILED = -20
    FAILED_REMOTE_EXPLOIT = -50

    # penalty for attempting to connect or execute an action on a node that's not in running state
    MACHINE_NOT_RUNNING = 0

    # penalty for attempting a connection with an invalid password
    WRONG_PASSWORD = -10

    # traffice blocked by outoing rule in a local firewall
    BLOCKED_BY_LOCAL_FIREWALL = -10

    # traffice blocked by incoming rule in a remote firewall
    BLOCKED_BY_REMOTE_FIREWALL = -10

    NODE_NOT_FIND = -10
    NODE_NOT_OWNED = -10

# Reward for any successfully executed local or remote attack
# (the attack cost gets substracted from this reward)
SUCCEEDED_ATTACK_REWARD = 50


class EdgeAnnotation(Enum):
    """Annotation added to the network edges created as the simulation is played"""
    KNOWS = 1
    REMOTE_EXPLOIT = 2
    LATERAL_MOVE = 3


class ActionResult(NamedTuple):
    """Result from executing an action"""
    reward: Reward
    outcome: Optional[model.VulnerabilityOutcome]


ALGEBRA = boolean.BooleanAlgebra()
ALGEBRA.TRUE.dual = type(ALGEBRA.FALSE)
ALGEBRA.FALSE.dual = type(ALGEBRA.TRUE)


@dataclass
class NodeTrackingInformation:
    """Track information about nodes gathered throughout the simulation"""
    # true: local false: remote
    last_attack: Dict[Tuple[model.VulnerabilityID, bool], time] = dataclasses.field(default_factory=dict)
    # Last time another node connected to this node
    last_connection: Optional[time] = None
    # All node properties discovered so far
    discovered_properties: Set[int] = dataclasses.field(default_factory=set)


class AgentActions:
    """
        This is the AgentAction class. It interacts with and makes changes to the environment.
    """

    def __init__(self, environment: model.Environment):
        """
            AgentActions Constructor
        """
        self._environment = environment
        self._gathered_credentials: Set[model.CredentialID] = set()
        self._discovered_nodes: "OrderedDict[model.NodeID, NodeTrackingInformation]" = OrderedDict()

        # List of all special tags indicating a privilege level reached on a node
        self.privilege_tags = [model.PrivilegeEscalation(p).tag for p in list(PrivilegeLevel)]

        # Mark all owned nodes as discovered
        for i, node in environment.nodes():
            if node.agent_installed:
                self.__mark_node_as_owned(i, PrivilegeLevel.LocalUser)

    def discovered_nodes(self) -> Iterator[Tuple[model.NodeID, model.NodeInfo]]:
        for node_id in self._discovered_nodes:
            yield (node_id, self._environment.get_node(node_id))

    def _check_prerequisites(self, target: model.NodeID, vulnerability: model.VulnerabilityInfo) -> bool:
        """
        This is a quick helper function to check the prerequisites to see if
        they match the ones supplied.
        """
        node: model.NodeInfo = self._environment.network.nodes[target]['data']
        node_flags = node.properties
        expr = vulnerability.precondition.expression

        # this line seems redundant but it is necessary to declare the symbols used in the mapping
        # pylint: disable=unused-variable

        mapping = {i: ALGEBRA.TRUE if str(i) in node_flags else ALGEBRA.FALSE
                   for i in expr.get_symbols()}
        is_true: bool = cast(boolean.Expression, expr.subs(mapping)).simplify() == ALGEBRA.TRUE
        return is_true

    def __annotate_edge(self, source_node_id: model.NodeID,
                        target_node_id: model.NodeID,
                        new_annotation: EdgeAnnotation) -> None:
        """Create the edge if it does not already exist, and annotate with the maximum
        of the existing annotation and a specified new annotation"""
        edge_annotation = self._environment.network.get_edge_data(source_node_id, target_node_id)

        if (edge_annotation is not None) and (edge_annotation):
            if 'kind' in edge_annotation:
                new_annotation = EdgeAnnotation(max(edge_annotation['kind'].value, new_annotation.value))
            else:
                new_annotation = new_annotation.value
        self._environment.network.add_edge(source_node_id, target_node_id, kind=new_annotation,
                                           kind_as_float=float(new_annotation.value))

    def get_discovered_properties(self, node_id: model.NodeID) -> Set[int]:
        return self._discovered_nodes[node_id].discovered_properties

    def __mark_node_as_discovered(self, node_id: model.NodeID) -> None:
        logger.info('discovered node: ' + node_id)
        if node_id not in self._discovered_nodes:
            self._discovered_nodes[node_id] = NodeTrackingInformation()

    def __mark_nodeproperties_as_discovered(self, node_id: model.NodeID, properties: List[PropertyName]):
        properties_indices = [self._environment.identifiers.properties.index(p)
                              for p in properties
                              if p not in self.privilege_tags]
        if node_id in self._discovered_nodes:
            self._discovered_nodes[node_id].discovered_properties = self._discovered_nodes[node_id].\
                discovered_properties.union(properties_indices)
        else:
            self._discovered_nodes[node_id] = NodeTrackingInformation(discovered_properties=set(properties_indices))

    def __mark_allnodeproperties_as_discovered(self, node_id: model.NodeID):
        node_info: model.NodeInfo = self._environment.network.nodes[node_id]['data']
        self.__mark_nodeproperties_as_discovered(node_id, node_info.properties)

    def __mark_node_as_owned(self,
                             node_id: model.NodeID,
                             privilege: PrivilegeLevel = model.PrivilegeLevel.LocalUser) -> None:
        if node_id not in self._discovered_nodes:
            self._discovered_nodes[node_id] = NodeTrackingInformation()
        node_info = self._environment.get_node(node_id)
        node_info.agent_installed = True
        node_info.privilege_level = model.escalate(node_info.privilege_level, privilege)
        self._environment.network.nodes[node_id].update({'data': node_info})

        self.__mark_allnodeproperties_as_discovered(node_id)

    def __mark_discovered_entities(self, reference_node: model.NodeID, outcome: model.VulnerabilityOutcome) -> None:
        if isinstance(outcome, model.LeakedCredentials):
            for credential in outcome.credentials:
                self.__mark_node_as_discovered(credential.node)
                self._gathered_credentials.add(credential.credential)
                logger.info('discovered credential: ' + str(credential))
                self.__annotate_edge(reference_node, credential.node, EdgeAnnotation.KNOWS)
                self.__mark_allnodeproperties_as_discovered(credential.node)

        elif isinstance(outcome, model.LeakedNodesId):
            for node_id in outcome.nodes:
                self.__mark_node_as_discovered(node_id)
                self.__annotate_edge(reference_node, node_id, EdgeAnnotation.KNOWS)
                self.__mark_allnodeproperties_as_discovered(node_id)

    def get_node_privilegelevel(self, node_id: model.NodeID) -> model.PrivilegeLevel:
        """Return the last recorded privilege level of the specified node"""
        node_info = self._environment.get_node(node_id)
        return node_info.privilege_level

    def get_nodes_with_atleast_privilegelevel(self, level: PrivilegeLevel) -> List[model.NodeID]:
        """Return all nodes with at least the specified privilege level"""
        return [n for n, info in self._environment.nodes() if info.privilege_level >= level]

    def __process_outcome(self,
                          expected_type: VulnerabilityType,
                          vulnerability_id: VulnerabilityID,
                          node_id: model.NodeID,
                          node_info: model.NodeInfo,
                          local_or_remote: bool,
                          failed_penalty: float,
                          throw_if_vulnerability_not_present: bool
                          ) -> Tuple[bool, ActionResult]:

        if node_info.status != model.MachineStatus.Running:
            logger.info("target machine not in running state")
            return False, ActionResult(reward=Penalty.MACHINE_NOT_RUNNING,
                                       outcome=None)

        is_global_vulnerability = vulnerability_id in self._environment.vulnerability_library
        is_inplace_vulnerability = vulnerability_id in node_info.vulnerabilities

        if is_global_vulnerability:
            vulnerabilities = self._environment.vulnerability_library
        elif is_inplace_vulnerability:
            vulnerabilities = node_info.vulnerabilities
        else:
            if throw_if_vulnerability_not_present:
                raise ValueError(f"Vulnerability '{vulnerability_id}' not supported by node='{node_id}'")
            else:
                logger.info(f"Vulnerability '{vulnerability_id}' not supported by node '{node_id}'")
                return False, ActionResult(reward=Penalty.SUPSPICIOUSNESS, outcome=None)

        vulnerability = vulnerabilities[vulnerability_id]
        outcome = vulnerability.outcome


        if vulnerability.type != expected_type:
            raise ValueError(f"vulnerability id '{vulnerability_id}' is for an attack of type {vulnerability.type}, "
                             f"expecting: {expected_type}")

        # check vulnerability prerequisites
        if not self._check_prerequisites(node_id, vulnerability):
            return False, ActionResult(reward=failed_penalty, outcome=model.ExploitFailed())

        # if the vulnerability type is a privilege escalation
        # and if the escalation level is not already reached on that node,
        # then add the escalation tag to the node properties
        if isinstance(outcome, model.PrivilegeEscalation):
            if outcome.tag in node_info.properties:
                return False, ActionResult(reward=Penalty.REPEAT, outcome=outcome)

            self.__mark_node_as_owned(node_id, outcome.level)

            node_info.properties.append(outcome.tag)

        elif isinstance(outcome, model.ProbeSucceeded):
            for p in outcome.discovered_properties:
                assert p in node_info.properties, \
                    f'Discovered property {p} must belong to the set of properties associated with the node.'

            self.__mark_nodeproperties_as_discovered(node_id, outcome.discovered_properties)

        if node_id not in self._discovered_nodes:
            self._discovered_nodes[node_id] = NodeTrackingInformation()

        lookup_key = (vulnerability_id, local_or_remote)

        already_executed = lookup_key in self._discovered_nodes[node_id].last_attack

        if already_executed:
            return False, ActionResult(reward=Penalty.REPEAT, outcome=outcome)

        self._discovered_nodes[node_id].last_attack[lookup_key] = time()

        self.__mark_discovered_entities(node_id, outcome)
        logger.info("GOT REWARD: " + vulnerability.reward_string)
        return True, ActionResult(reward=0.0 if already_executed else SUCCEEDED_ATTACK_REWARD - vulnerability.cost,
                                  outcome=vulnerability.outcome)

    def exploit_remote_vulnerability(self,
                                     node_id: model.NodeID,
                                     target_node_id: model.NodeID,
                                     vulnerability_id: model.VulnerabilityID
                                     ) -> ActionResult:
        """
        Attempt to exploit a remote vulnerability
        from a source node to another node using the specified
        vulnerability.
        """

        if node_id not in self._environment.network.nodes:
            result = ActionResult(reward=Penalty.NODE_NOT_FIND, outcome=None)
            return result
        if target_node_id not in self._environment.network.nodes:
            result = ActionResult(reward=Penalty.NODE_NOT_FIND, outcome=None)
            return result

        if node_id == target_node_id:
            result = ActionResult(reward=Penalty.SUPSPICIOUSNESS, outcome=None)
            return result
        source_node_info: model.NodeInfo = self._environment.get_node(node_id)
        target_node_info: model.NodeInfo = self._environment.get_node(target_node_id)

        if not source_node_info.agent_installed:
            result = ActionResult(reward=Penalty.NODE_NOT_OWNED, outcome=None)
            return result

        if target_node_id not in self._discovered_nodes:
            result = ActionResult(reward=Penalty.NODE_NOT_FIND, outcome=None)
            return result

        succeeded, result = self.__process_outcome(
            model.VulnerabilityType.REMOTE,
            vulnerability_id,
            target_node_id,
            target_node_info,
            local_or_remote=False,
            failed_penalty=Penalty.FAILED_REMOTE_EXPLOIT,
            throw_if_vulnerability_not_present=False
        )

        if succeeded:
            self.__annotate_edge(node_id, target_node_id, EdgeAnnotation.REMOTE_EXPLOIT)

        return result

    def exploit_local_vulnerability(self, node_id: model.NodeID,
                                    vulnerability_id: model.VulnerabilityID) -> ActionResult:
        """
            This function exploits a local vulnerability on a node
            it takes a nodeID for the target and a vulnerability ID.

            It returns either a vulnerabilityoutcome object or None
        """
        graph = self._environment.network

        if node_id not in graph.nodes:
            result = ActionResult(reward=Penalty.NODE_NOT_FIND, outcome=None)
            return result

        node_info = self._environment.get_node(node_id)

        if not node_info.agent_installed:
            result = ActionResult(reward=Penalty.NODE_NOT_OWNED, outcome=None)
            return result

        succeeded, result = self.__process_outcome(
            model.VulnerabilityType.LOCAL,
            vulnerability_id,
            node_id, node_info,
            local_or_remote=True,
            failed_penalty=Penalty.LOCAL_EXPLOIT_FAILED,
            throw_if_vulnerability_not_present=False)

        return result

    def __is_passing_firewall_rules(self, rules: List[model.FirewallRule], port_name: model.PortName) -> bool:
        """Determine if traffic on the specified port is permitted by the specified sets of firewall rules"""
        for rule in rules:
            if rule.port == port_name:
                if rule.permission == model.RulePermission.ALLOW:
                    return True
                else:
                    logger.debug(f'BLOCKED TRAFFIC - PORT \'{port_name}\' Reason: ' + rule.reason)
                    return False

        logger.debug(f"BLOCKED TRAFFIC - PORT '{port_name}' - Reason: no rule defined for this port.")
        return False

    def connect_to_remote_machine(
            self,
            source_node_id: model.NodeID,
            target_node_id: model.NodeID,
            port_name: model.PortName,
            credential: model.CredentialID) -> ActionResult:
        """
            This function connects to a remote machine with credential as opposed to via an exploit.
            It takes a NodeId for the source machine, a NodeID for the target Machine, and a credential object
            for the credential.
            此函数使用凭据(而不是通过漏洞)连接到远程机器。它接受源机器的NodeId、目标机器的NodeId和凭据的凭据对象。
        """
        graph = self._environment.network
        if source_node_id not in graph.nodes:
            result = ActionResult(reward=Penalty.NODE_NOT_FIND, outcome=None)
            return result

        if target_node_id not in graph.nodes:
            result = ActionResult(reward=Penalty.NODE_NOT_FIND, outcome=None)
            return result

        if source_node_id == target_node_id:
            result = ActionResult(reward=Penalty.SUPSPICIOUSNESS, outcome=None)
            return result

        target_node = self._environment.get_node(target_node_id)
        source_node = self._environment.get_node(source_node_id)

        if not source_node.agent_installed:
            result = ActionResult(reward=Penalty.NODE_NOT_OWNED, outcome=None)
            return result

        if target_node_id not in self._discovered_nodes:
            result = ActionResult(reward=Penalty.NODE_NOT_FIND, outcome=None)
            return result

        if credential not in self._gathered_credentials:
            result = ActionResult(reward=Penalty.NODE_NOT_FIND, outcome=None)
            return result

        if not self.__is_passing_firewall_rules(source_node.firewall.outgoing, port_name):
            logger.info(f"BLOCKED TRAFFIC: source node '{source_node_id}'" +
                        f" is blocking outgoing traffic on port '{port_name}'")
            return ActionResult(reward=Penalty.BLOCKED_BY_LOCAL_FIREWALL,
                                outcome=None)

        if not self.__is_passing_firewall_rules(target_node.firewall.incoming, port_name):
            logger.info(f"BLOCKED TRAFFIC: target node '{target_node_id}'" +
                        f" is blocking outgoing traffic on port '{port_name}'")
            return ActionResult(reward=Penalty.BLOCKED_BY_REMOTE_FIREWALL,
                                outcome=None)

        target_node_is_listening = port_name in [i.name for i in target_node.services]
        if not target_node_is_listening:
            logger.info(f"target node '{target_node_id}' not listening on port '{port_name}'")
            return ActionResult(reward=Penalty.SCANNING_UNOPEN_PORT,
                                outcome=None)
        else:
            target_node_data: model.NodeInfo = self._environment.get_node(target_node_id)

            if target_node_data.status != model.MachineStatus.Running:
                logger.info("target machine not in running state")
                return ActionResult(reward=Penalty.MACHINE_NOT_RUNNING,
                                    outcome=None)

            # check the credentials before connecting
            if not self._check_service_running_and_authorized(target_node_data, port_name, credential):
                logger.info("invalid credentials supplied")
                return ActionResult(reward=Penalty.WRONG_PASSWORD,
                                    outcome=None)

            is_already_owned = target_node_data.agent_installed
            if is_already_owned:
                return ActionResult(reward=Penalty.REPEAT,
                                    outcome=model.LateralMove())

            if target_node_id not in self._discovered_nodes:
                self._discovered_nodes[target_node_id] = NodeTrackingInformation()

            was_previously_owned_at = self._discovered_nodes[target_node_id].last_connection
            self._discovered_nodes[target_node_id].last_connection = time()

            if was_previously_owned_at is not None:
                return ActionResult(reward=Penalty.REPEAT, outcome=model.LateralMove())

            self.__annotate_edge(source_node_id, target_node_id, EdgeAnnotation.LATERAL_MOVE)
            self.__mark_node_as_owned(target_node_id)
            logger.info(f"Infected node '{target_node_id}' from '{source_node_id}'" +
                        f" via {port_name} with credential '{credential}'")
            if target_node.owned_string:
                logger.info("Owned message: " + target_node.owned_string)

            return ActionResult(reward=float(target_node_data.value) if was_previously_owned_at is None else 0.0,
                                outcome=model.LateralMove())

    def _check_service_running_and_authorized(self,
                                              target_node_data: model.NodeInfo,
                                              port_name: model.PortName,
                                              credential: model.CredentialID) -> bool:
        """
            This is a quick helper function to check the prerequisites to see if
            they match the ones supplied.
        """
        for service in target_node_data.services:
            if service.running and service.name == port_name and credential in service.allowedCredentials:
                return True
        return False







