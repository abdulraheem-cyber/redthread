from __future__ import annotations

from redthread.agents.auth import AuthenticationAgent, parse_forms
from redthread.audit import AuditLog
from redthread.budget import RunBudget
from redthread.graph import Graph
from redthread.http import HttpSession
from redthread.ratelimit import RateLimiter
from redthread.scope import Scope
from tests.helpers import write_config


def test_parse_forms_picks_password_form():
    html = """\
    <form method="get" action="/search"><input name="q"></form>
    <form method="post" action="/login">
      <input type="hidden" name="csrf" value="abc">
      <input type="text" name="username">
      <input type="password" name="password">
      <button type="submit" name="go" value="1">Sign in</button>
    </form>
    """
    forms = parse_forms(html)
    assert len(forms) == 2
    login = forms[1]
    assert login.method == "POST"
    assert login.has_password()
    assert login.named()["csrf"] == "abc"


async def test_form_login_against_lab(tmp_path, lab):
    config = write_config(tmp_path / "redthread.toml", lab.base_url)
    scope = Scope(config)
    graph = Graph(tmp_path / "graph.sqlite")
    audit = AuditLog(tmp_path / "audit.jsonl", "test")
    budget = RunBudget(40, 30)
    session = HttpSession("alice", scope, RateLimiter(0), budget, audit)
    try:
        agent = AuthenticationAgent(config, graph, audit)
        result = await agent.authenticate(session, config.identity("alice"))
        assert result.ok, result.detail
        assert "sid" in result.cookies
        account = await session.request("GET", lab.base_url + "/account")
        assert account.status == 200
        assert "Signed in as alice" in account.text

        node = graph.get_node("identity", "alice")
        assert node and node["props"]["authenticated"] is True
    finally:
        await session.close()
        audit.close()
        graph.close()
