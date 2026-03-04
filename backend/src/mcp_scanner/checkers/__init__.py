from mcp_scanner.checkers.base import BaseChecker
from mcp_scanner.checkers.data_exfiltration import DataExfiltrationChecker
from mcp_scanner.checkers.infra_security import InfraSecurityChecker
from mcp_scanner.checkers.injection import InjectionChecker
from mcp_scanner.checkers.rug_pull import RugPullChecker
from mcp_scanner.checkers.supply_chain import SupplyChainChecker
from mcp_scanner.checkers.tool_poisoning import ToolPoisoningChecker


def get_all_checkers() -> list[BaseChecker]:
    return [
        ToolPoisoningChecker(),
        RugPullChecker(),
        DataExfiltrationChecker(),
        SupplyChainChecker(),
        InfraSecurityChecker(),
        InjectionChecker(),
    ]
