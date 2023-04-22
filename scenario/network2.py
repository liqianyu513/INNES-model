from simulation.model import Identifiers, NodeID, NodeInfo
from simulation import model as m

DEFAULT_ALLOW_RULES = [
    m.FirewallRule("RDP", m.RulePermission.ALLOW),
    m.FirewallRule("SMB", m.RulePermission.ALLOW),
    m.FirewallRule("SSH", m.RulePermission.ALLOW),
    m.FirewallRule("MySql", m.RulePermission.ALLOW)]

# Environment constants used for all instances of the chain network mysql 3306

ENV_IDENTIFIERS = Identifiers(
    properties=[
        'Windows_7',
        'Windows_XP',
        'Windows_Server_2003',
        'Windows_Server_2008',
        'Windows_Server_2012',
        'Ubuntu_16.04_4.4.110',
        'Weblogic_12.3.1',
        'Struts_2.3.24',
        'E_cology_9.0',
        'RDP',
        'SMB',
        'SSH',
        'MySql'
    ],
    ports=[
        'RDP',
        'SMB',
        'SSH',
        'MySql'
    ],
    local_vulnerabilities=[
        'CVE_2017_16995',
        'CVE_2009_0079',
        'MS15_015',
        'MS16_111',
        'CVE_2022_0847',
        'Search'
    ],
    remote_vulnerabilities=[
        'CVE_2019_2729',
        'S2_048',
        'MS17_010',
        'MS08_067',
        'CNVD_2019_32204',
        'CVE_2019_0708',
        'MS09_050'
    ]
)

nodes = {
    "start": m.NodeInfo(
        services=[],
        vulnerabilities=dict(
            Search=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["A", "B"]),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=1.0
            ),
            MS16_111=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.AdminEscalation(),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=1.0
            )
        ),
        value=0,
        properties=["Windows_Server_2008"],
        agent_installed=True
    ),
    "A": m.NodeInfo(
        services=[],
        vulnerabilities=dict(
            CVE_2017_16995=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="C",
                                                                            port="MySql",
                                                                            credential="Mysql-Conf-file")]),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=1.0
            ),
            CVE_2019_2729=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.AdminEscalation(),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=1.0,
            )
        ),
        value=30,
        properties=["Ubuntu_16.04_4.4.110", "Weblogic_12.3.1"],
    ),
    "B": m.NodeInfo(
        services=[],
        vulnerabilities=dict(
            CVE_2009_0079=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="D",
                                                                            port="RDP",
                                                                            credential="RDPCreds")]),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=5.0
            ),
            S2_048=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.SystemEscalation(),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=1.0
            )
        ),
        value=50,
        properties=["Windows_Server_2003", "Struts_2.3.24"]
    ),
    "C": m.NodeInfo(
        services=[m.ListeningService("MySql", allowedCredentials=["Mysql-Conf-file"])],
        vulnerabilities=dict(
            CVE_2017_16995=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["E"]),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=1.0
            )
        ),
        value=60,
        properties=["Ubuntu_16.04_4.4.110", "MySql"]
    ),
    "D": m.NodeInfo(
        services=[m.ListeningService("RDP", allowedCredentials=["RDPCreds"])],
        vulnerabilities=dict(
            MS15_015=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["F"]),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=1.0
            ),
            CNVD_2019_32204=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.SystemEscalation(),
                # precondition=m.Precondition('True'),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=1.0
            )
        ),
        value=60,
        properties=["Windows_Server_2012", "E_cology_9.0", "RDP"]
    ),
    "E": m.NodeInfo(
        services=[],
        vulnerabilities=dict(
            MS17_010=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedNodesId(["G"]),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=5.0
            ),
            MS16_111=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["H"]),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=1.0
            )
        ),
        value=100,
        properties=["Windows_7", "SMB"]
    ),
    "F": m.NodeInfo(
        services=[],
        vulnerabilities=dict(
            MS17_010=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.SystemEscalation(),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=5.0
            ),
            CVE_2009_0079=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["H"]),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=5.0
            )
        ),
        value=20,
        properties=["Windows_Server_2003", "SMB"]
    ),
    "G": m.NodeInfo(
        services=[],
        vulnerabilities=dict(
            MS08_067=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedNodesId(["I"]),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=1.0
            )),
        value=300,
        properties=["Windows_XP", "SMB"]
    ),
    "H": m.NodeInfo(
        services=[],
        vulnerabilities=dict(
            CVE_2019_0708=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.AdminEscalation(),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=2.0
            )
        ),
        value=50,
        properties=["Windows_7", "RDP"]
    ),
    "I": m.NodeInfo(
        services=[],
        vulnerabilities=dict(
            S2_048=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.SystemEscalation(),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=1.0
            ),
            CVE_2022_0847=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.AdminEscalation(),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=1.0
            )
        ),
        value=1000,
        properties=["Ubuntu_16.04_4.4.110", "Struts_2.3.24"],
    )
}
global_vulnerability_library = dict([])


def new_environment() -> m.Environment:
    return m.Environment(
        network=m.create_network(nodes),
        vulnerability_library=global_vulnerability_library,
        identifiers=ENV_IDENTIFIERS
    )

