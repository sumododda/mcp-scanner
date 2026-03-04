from mcp_scanner.checkers import get_all_checkers
from mcp_scanner.checkers.base import BaseChecker


def test_all_checkers_registered():
    checkers = get_all_checkers()
    assert len(checkers) == 6
    assert all(isinstance(c, BaseChecker) for c in checkers)
    names = {c.name for c in checkers}
    assert "tool_poisoning" in names
    assert "rug_pull" in names
    assert "data_exfiltration" in names
    assert "supply_chain" in names
    assert "infra_security" in names
    assert "injection" in names
