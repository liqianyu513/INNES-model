from simulation import model as m
from simulation.model import NodeID, NodeInfo, VulnerabilityID, VulnerabilityInfo
from typing import Dict, Iterator, cast, Tuple

nodes = {
    '0': m.NodeInfo(
        services=[m.ListeningService("HTTPS", allowedCredentials=["ADPrincipalCreds"])],
        value=87,
        properties=["HTTPS"],
        agent_installed=False,
        privilege_level=m.PrivilegeLevel.NoAccess,
        owned_string='',
        sla_weight=1.0,
        firewall=m.FirewallConfiguration(outgoing=[m.FirewallRule("PortRDPOpen", m.RulePermission.ALLOW),
                                                   m.FirewallRule("HyperV-VM", m.RulePermission.ALLOW),
                                                   m.FirewallRule("Win7", m.RulePermission.ALLOW),
                                                   m.FirewallRule("GuestAccountEnabled", m.RulePermission.ALLOW),
                                                   m.FirewallRule("Win10", m.RulePermission.ALLOW),
                                                   m.FirewallRule("Azure-VM", m.RulePermission.ALLOW),
                                                   m.FirewallRule("HTTPS", m.RulePermission.ALLOW),
                                                   ],
                                         incoming=[m.FirewallRule("Win10", m.RulePermission.ALLOW),
                                                   m.FirewallRule("HTTPS", m.RulePermission.ALLOW),
                                                   ]),
        vulnerabilities=dict(
            UACME61=m.VulnerabilityInfo(
                description='UACME UAC bypass #61',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.AdminEscalation(),
                rates=m.Rates(probingDetectionRate=0,
                              exploitDetectionRate=0.2,
                              successRate=1.0),
                reward_string=''
            ),
            UACME67=m.VulnerabilityInfo(
                description='UACME UAC bypass #67 (fake system escalation) ',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.SystemEscalation(),
                rates=m.Rates(probingDetectionRate=0,
                              exploitDetectionRate=0.2,
                              successRate=1.0),
                reward_string=''
            ),
            MimikatzLogonpasswords=m.VulnerabilityInfo(
                description='Mimikatz sekurlsa::logonpasswords.',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node='3',
                                       port="HTTPS",
                                       credential="SASTOKEN1")]),
                rates=m.Rates(probingDetectionRate=0,
                              exploitDetectionRate=1.0,
                              successRate=1.0),
                reward_string=''
            ),
            RecentlyAccessedMachines=m.VulnerabilityInfo(
                description='AzureVM info, including public IP address',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(['1', '3', '4']),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                reward_string=''
            ))
    ),
    '1': m.NodeInfo(
        services=[],
        value=86,
        properties=[],
        agent_installed=False,
        privilege_level=m.PrivilegeLevel.NoAccess,
        owned_string='',
        sla_weight=1.0,
        firewall=m.FirewallConfiguration(outgoing=[m.FirewallRule("PortRDPOpen", m.RulePermission.ALLOW),
                                                   m.FirewallRule("Azure-VM", m.RulePermission.ALLOW),
                                                   m.FirewallRule("HTTPS", m.RulePermission.ALLOW),
                                                   ],
                                         incoming=[m.FirewallRule("HTTPS", m.RulePermission.ALLOW),
                                                   ]),
        vulnerabilities=dict(
            UACME61=m.VulnerabilityInfo(
                description='UACME UAC bypass #61',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.AdminEscalation(),
                rates=m.Rates(probingDetectionRate=0,
                              exploitDetectionRate=0.2,
                              successRate=1.0),
                reward_string=''
            ),
            UACME67=m.VulnerabilityInfo(
                description='UACME UAC bypass #67 (fake system escalation) ',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.SystemEscalation(),
                rates=m.Rates(probingDetectionRate=0,
                              exploitDetectionRate=0.2,
                              successRate=1.0),
                reward_string=''
            ),
            MimikatzLogonpasswords=m.VulnerabilityInfo(
                description='Mimikatz sekurlsa::logonpasswords.',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node='0',
                                       port="HTTPS",
                                       credential="ADPrincipalCreds")]),
                rates=m.Rates(probingDetectionRate=0,
                              exploitDetectionRate=1.0,
                              successRate=1.0),
                reward_string=''
            ),
            RDPBF=m.VulnerabilityInfo(
                description='RDP Brute Force',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.SystemEscalation(),
                rates=m.Rates(probingDetectionRate=0,
                              exploitDetectionRate=0.2,
                              successRate=1.0),
                reward_string=''
            ),
            RecentlyAccessedMachines=m.VulnerabilityInfo(
                description='AzureVM info, including public IP address',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(['0', '7', '2']),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                reward_string=''
            ))
    ),
    '2': m.NodeInfo(
        services=[],
        value=57,
        properties=["GuestAccountEnabled", "HyperV-VM", "Azure-VM", "Win7", "Win10", "PortRDPOpen", "Windows"],
        agent_installed=False,
        privilege_level=m.PrivilegeLevel.NoAccess,
        owned_string='',
        sla_weight=1.0,
        firewall=m.FirewallConfiguration(outgoing=[m.FirewallRule("PortRDPOpen", m.RulePermission.ALLOW),
                                                   m.FirewallRule("HTTPS", m.RulePermission.ALLOW),
                                                   ],
                                         incoming=[m.FirewallRule("Win10", m.RulePermission.ALLOW),
                                                   m.FirewallRule("Azure-VM", m.RulePermission.ALLOW),
                                                   m.FirewallRule("GuestAccountEnabled", m.RulePermission.ALLOW),
                                                   m.FirewallRule("HyperV-VM", m.RulePermission.ALLOW),
                                                   m.FirewallRule("Linux", m.RulePermission.ALLOW),
                                                   m.FirewallRule("HTTPS", m.RulePermission.ALLOW),
                                                   m.FirewallRule("PortRDPOpen", m.RulePermission.ALLOW),
                                                   m.FirewallRule("Windows", m.RulePermission.ALLOW),
                                                   ]),
        vulnerabilities=dict(
            UACME61=m.VulnerabilityInfo(
                description='UACME UAC bypass #61',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.AdminEscalation(),
                rates=m.Rates(probingDetectionRate=0,
                              exploitDetectionRate=0.2,
                              successRate=1.0),
                reward_string=''
            ),
            MimikatzLogonpasswords=m.VulnerabilityInfo(
                description='Mimikatz sekurlsa::logonpasswords.',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node='3',
                                       port="HTTPS",
                                       credential="SASTOKEN1")]),
                rates=m.Rates(probingDetectionRate=0,
                              exploitDetectionRate=1.0,
                              successRate=1.0),
                reward_string=''
            ),
            RDPBF=m.VulnerabilityInfo(
                description='RDP Brute Force',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.SystemEscalation(),
                rates=m.Rates(probingDetectionRate=0,
                              exploitDetectionRate=0.2,
                              successRate=1.0),
                reward_string=''
            ),
            RecentlyAccessedMachines=m.VulnerabilityInfo(
                description='AzureVM info, including public IP address',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(['1', '6', '3']),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                reward_string=''
            ))
    ),
    '3': m.NodeInfo(
        services=[m.ListeningService("HTTPS", allowedCredentials=["SASTOKEN1"])],
        value=43,
        properties=["Linux", "HTTPS"],
        agent_installed=False,
        privilege_level=m.PrivilegeLevel.NoAccess,
        owned_string='',
        sla_weight=1.0,
        firewall=m.FirewallConfiguration(outgoing=[m.FirewallRule("HyperV-VM", m.RulePermission.ALLOW),
                                                   m.FirewallRule("GuestAccountEnabled", m.RulePermission.ALLOW),
                                                   m.FirewallRule("HTTPS", m.RulePermission.ALLOW),
                                                   ],
                                         incoming=[m.FirewallRule("Linux", m.RulePermission.ALLOW),
                                                   m.FirewallRule("Win7", m.RulePermission.ALLOW),
                                                   m.FirewallRule("PortRDPOpen", m.RulePermission.ALLOW),
                                                   m.FirewallRule("HTTPS", m.RulePermission.ALLOW),
                                                   ]),
        vulnerabilities=dict(
            UACME61=m.VulnerabilityInfo(
                description='UACME UAC bypass #61',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.AdminEscalation(),
                rates=m.Rates(probingDetectionRate=0,
                              exploitDetectionRate=0.2,
                              successRate=1.0),
                reward_string=''
            ),
            UACME67=m.VulnerabilityInfo(
                description='UACME UAC bypass #67 (fake system escalation) ',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.SystemEscalation(),
                rates=m.Rates(probingDetectionRate=0,
                              exploitDetectionRate=0.2,
                              successRate=1.0),
                reward_string=''
            ),
            MimikatzLogonpasswords=m.VulnerabilityInfo(
                description='Mimikatz sekurlsa::logonpasswords.',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node='0',
                                       port="HTTPS",
                                       credential="ADPrincipalCreds")]),
                rates=m.Rates(probingDetectionRate=0,
                              exploitDetectionRate=1.0,
                              successRate=1.0),
                reward_string=''
            ),
            RecentlyAccessedMachines=m.VulnerabilityInfo(
                description='AzureVM info, including public IP address',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(['0', '5', '2']),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                reward_string=''
            ))
    ),
    '4': m.NodeInfo(
        services=[m.ListeningService("HTTP", allowedCredentials=["HTTPCreds"])],
        value=20,
        properties=["PortRDPOpen", "Win10", "HyperV-VM", "Windows", "Azure-VM", "Linux", "GuestAccountEnabled", "HTTP"],
        agent_installed=False,
        privilege_level=m.PrivilegeLevel.NoAccess,
        owned_string='',
        sla_weight=1.0,
        firewall=m.FirewallConfiguration(outgoing=[m.FirewallRule("GuestAccountEnabled", m.RulePermission.ALLOW),
                                                   m.FirewallRule("HTTP", m.RulePermission.ALLOW),
                                                   ],
                                         incoming=[m.FirewallRule("PortRDPOpen", m.RulePermission.ALLOW),
                                                   m.FirewallRule("GuestAccountEnabled", m.RulePermission.ALLOW),
                                                   m.FirewallRule("HTTP", m.RulePermission.ALLOW),
                                                   ]),
        vulnerabilities=dict(
            UACME61=m.VulnerabilityInfo(
                description='UACME UAC bypass #61',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.AdminEscalation(),
                rates=m.Rates(probingDetectionRate=0,
                              exploitDetectionRate=0.2,
                              successRate=1.0),
                reward_string=''
            ),
            UACME67=m.VulnerabilityInfo(
                description='UACME UAC bypass #67 (fake system escalation) ',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.SystemEscalation(),
                rates=m.Rates(probingDetectionRate=0,
                              exploitDetectionRate=0.2,
                              successRate=1.0),
                reward_string=''
            ),
            MimikatzLogonpasswords=m.VulnerabilityInfo(
                description='Mimikatz sekurlsa::logonpasswords.',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node='7',
                                       port="HTTPS",
                                       credential="ADPrincipalCreds")]),
                rates=m.Rates(probingDetectionRate=0,
                              exploitDetectionRate=1.0,
                              successRate=1.0),
                reward_string=''
            ),
            RecentlyAccessedMachines=m.VulnerabilityInfo(
                description='AzureVM info, including public IP address',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(['0', '7', '5']),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                reward_string=''
            ))
    ),
    '5': m.NodeInfo(
        services=[],
        value=64,
        properties=["Win10", "PortRDPOpen", "HyperV-VM", "Linux", "Azure-VM", "GuestAccountEnabled"],
        agent_installed=False,
        privilege_level=m.PrivilegeLevel.NoAccess,
        owned_string='',
        sla_weight=1.0,
        firewall=m.FirewallConfiguration(outgoing=[m.FirewallRule("Win10", m.RulePermission.ALLOW),
                                                   m.FirewallRule("HyperV-VM", m.RulePermission.ALLOW),
                                                   m.FirewallRule("Linux", m.RulePermission.ALLOW),
                                                   m.FirewallRule("HTTP", m.RulePermission.ALLOW),
                                                   ],
                                         incoming=[m.FirewallRule("GuestAccountEnabled", m.RulePermission.ALLOW),
                                                   m.FirewallRule("PortRDPOpen", m.RulePermission.ALLOW),
                                                   m.FirewallRule("HTTP", m.RulePermission.ALLOW),
                                                   ]),
        vulnerabilities=dict(
            UACME61=m.VulnerabilityInfo(
                description='UACME UAC bypass #61',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.AdminEscalation(),
                rates=m.Rates(probingDetectionRate=0,
                              exploitDetectionRate=0.2,
                              successRate=1.0),
                reward_string=''
            ),
            MimikatzLogonpasswords=m.VulnerabilityInfo(
                description='Mimikatz sekurlsa::logonpasswords.',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node='4',
                                       port="HTTP",
                                       credential="HTTPCreds")]),
                rates=m.Rates(probingDetectionRate=0,
                              exploitDetectionRate=1.0,
                              successRate=1.0),
                reward_string=''
            ),
            RDPBF=m.VulnerabilityInfo(
                description='RDP Brute Force',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.SystemEscalation(),
                rates=m.Rates(probingDetectionRate=0,
                              exploitDetectionRate=0.2,
                              successRate=1.0),
                reward_string=''
            ),
            RecentlyAccessedMachines=m.VulnerabilityInfo(
                description='AzureVM info, including public IP address',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(['6', '3', '4']),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                reward_string=''
            ))
    ),
    '6': m.NodeInfo(
        services=[],
        value=0,
        properties=["Linux", "HyperV-VM", "Win7", "GuestAccountEnabled", "Azure-VM"],
        agent_installed=True,
        privilege_level=m.PrivilegeLevel.NoAccess,
        owned_string='',
        sla_weight=1.0,
        firewall=m.FirewallConfiguration(outgoing=[m.FirewallRule("Windows", m.RulePermission.ALLOW),
                                                   m.FirewallRule("GuestAccountEnabled", m.RulePermission.ALLOW),
                                                   m.FirewallRule("HyperV-VM", m.RulePermission.ALLOW),
                                                   m.FirewallRule("PortRDPOpen", m.RulePermission.ALLOW),
                                                   ],
                                         incoming=[m.FirewallRule("Win7", m.RulePermission.ALLOW),
                                                   m.FirewallRule("PortRDPOpen", m.RulePermission.ALLOW),
                                                   m.FirewallRule("Win10", m.RulePermission.ALLOW),
                                                   ]),
        vulnerabilities=dict(
            RDPBF=m.VulnerabilityInfo(
                description='RDP Brute Force',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.SystemEscalation(),
                rates=m.Rates(probingDetectionRate=0,
                              exploitDetectionRate=0.2,
                              successRate=1.0),
                reward_string=''
            ),
            RecentlyAccessedMachines=m.VulnerabilityInfo(
                description='AzureVM info, including public IP address',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(['7', '2', '5']),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                reward_string=''
            ))
    ),
    '7': m.NodeInfo(
        services=[m.ListeningService("HTTPS", allowedCredentials=["ADPrincipalCreds"])],
        value=0,
        properties=["Win7", "HTTPS"],
        agent_installed=False,
        privilege_level=m.PrivilegeLevel.NoAccess,
        owned_string='',
        sla_weight=1.0,
        firewall=m.FirewallConfiguration(outgoing=[m.FirewallRule("Linux", m.RulePermission.ALLOW),
                                                   m.FirewallRule("Windows", m.RulePermission.ALLOW),
                                                   m.FirewallRule("HTTPS", m.RulePermission.ALLOW),
                                                   ],
                                         incoming=[m.FirewallRule("HyperV-VM", m.RulePermission.ALLOW),
                                                   m.FirewallRule("Win10", m.RulePermission.ALLOW),
                                                   m.FirewallRule("HTTPS", m.RulePermission.ALLOW),
                                                   m.FirewallRule("GuestAccountEnabled", m.RulePermission.ALLOW),
                                                   m.FirewallRule("Windows", m.RulePermission.ALLOW),
                                                   m.FirewallRule("Azure-VM", m.RulePermission.ALLOW),
                                                   m.FirewallRule("Linux", m.RulePermission.ALLOW),
                                                   ]),
        vulnerabilities=dict(
            UACME61=m.VulnerabilityInfo(
                description='UACME UAC bypass #61',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.AdminEscalation(),
                rates=m.Rates(probingDetectionRate=0,
                              exploitDetectionRate=0.2,
                              successRate=1.0),
                reward_string=''
            ),
            RDPBF=m.VulnerabilityInfo(
                description='RDP Brute Force',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.SystemEscalation(),
                rates=m.Rates(probingDetectionRate=0,
                              exploitDetectionRate=0.2,
                              successRate=1.0),
                reward_string=''
            ),
            RecentlyAccessedMachines=m.VulnerabilityInfo(
                description='AzureVM info, including public IP address',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(['1', '6', '4']),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                reward_string=''
            ))
    ),

}

global_vulnerability_library: Dict[VulnerabilityID, VulnerabilityInfo] = dict([])


def new_environment() -> m.Environment:
    return m.Environment(
        network=m.create_network(nodes),
        vulnerability_library=global_vulnerability_library,
        identifiers=m.SAMPLE_IDENTIFIERS1
    )
