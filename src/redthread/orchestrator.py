from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from redthread.agents.auth import AuthenticationAgent
from redthread.agents.explore import ExplorationAgent
from redthread.agents.managed import ManagedAgent
from redthread.agents.runner import ActionRunner
from redthread.agents.scan import ScanAgent
from redthread.audit import AuditLog
from redthread.budget import RunBudget
from redthread.checks import CheckContext, enabled_checks
from redthread.config import Config
from redthread.errors import BudgetExceeded, ConfigError, RunStopped, ScopeError
from redthread.graph import Graph
from redthread.http import HttpSession
from redthread.llm import build_llm
from redthread.models import Status, utcnow
from redthread.planner import MctsPlanner, baseline_order, build_check_actions
from redthread.ratelimit import RateLimiter
from redthread.reporting import build_report, write_reports
from redthread.scope import Scope

log = logging.getLogger(__name__)


@dataclass
class RunOutcome:
    run_dir: Path
    report: dict[str, Any]
    artifacts: dict[str, Path] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def validated(self) -> list[dict[str, Any]]:
        return list(self.report.get("findings", []))


class Orchestrator:
    def __init__(
        self,
        config: Config,
        *,
        no_llm: bool = False,
        no_explore: bool = False,
    ):
        self.config = config
        self.no_llm = no_llm
        self.no_explore = no_explore
        self.scope = Scope(config)
        self.graph: Graph | None = None
        self.audit: AuditLog | None = None
        self.run_dir: Path | None = None
        self._log_handler: logging.Handler | None = None

    async def run(self) -> RunOutcome:
        self.scope.require_authorization()
        stop_file = self.config.stop_file()
        if stop_file.exists():
            reason = stop_file.read_text(encoding="utf-8", errors="replace").strip()
            raise RunStopped(reason or f"stop file exists: {stop_file}")

        stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        self.run_dir = self.config.run_dir(stamp)
        if self.run_dir.exists():
            for index in range(2, 1000):
                candidate = Path(f"{self.run_dir}-{index}")
                if not candidate.exists():
                    self.run_dir = candidate
                    break
            else:
                raise ConfigError(f"too many runs share the timestamp {stamp}")
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self._attach_log()
        run_id = self.run_dir.name
        started_at = utcnow()

        graph_path = (
            Path(self.config.graph.path)
            if self.config.graph.path
            else self.run_dir / "graph.sqlite"
        )
        if not graph_path.is_absolute():
            graph_path = self.config.root / graph_path
        self.graph = Graph(graph_path.resolve())
        self.audit = AuditLog(self.run_dir / "audit.jsonl", run_id)
        budget = RunBudget(
            self.config.run.max_requests,
            self.config.run.max_runtime_seconds,
            stop_file,
        )
        limiter = RateLimiter(self.config.run.rate_limit)
        llm = build_llm(self.config.llm if not self.no_llm else self.config.with_llm(False).llm)
        try:
            checks = enabled_checks(self.config)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
        if not checks:
            raise ConfigError("all checks are disabled")

        anonymous = HttpSession(
            "anonymous",
            self.scope,
            limiter,
            budget,
            self.audit,
            headers={"User-Agent": self.config.run.user_agent},
            verify_tls=self.config.run.verify_tls,
        )
        sessions: dict[str, HttpSession] = {}
        all_sessions: list[HttpSession] = [anonymous]
        auth_results: list[dict[str, Any]] = []
        errors: list[str] = []
        scan_data: dict[str, Any] = {}
        stopped_reason = ""
        fatal: Exception | None = None

        self.graph.upsert_node(
            "run",
            run_id,
            started_at=started_at,
            engine="redthread",
            scope=list(self.config.scope.include),
        )
        try:
            auth_agent = AuthenticationAgent(self.config, self.graph, self.audit)
            for identity in self.config.identities:
                if identity.name == "anonymous":
                    raise ConfigError("'anonymous' is reserved and cannot be an identity name")
                session = HttpSession(
                    identity.name,
                    self.scope,
                    limiter,
                    budget,
                    self.audit,
                    headers={"User-Agent": self.config.run.user_agent},
                    verify_tls=self.config.run.verify_tls,
                )
                all_sessions.append(session)
                result = await auth_agent.authenticate(session, identity)
                auth_results.append(result.to_dict())
                if result.ok:
                    sessions[identity.name] = session
                else:
                    errors.append(f"auth {identity.name}: {result.detail}")
                    log.warning("authentication failed for %s: %s", identity.name, result.detail)

            scan_agent = ScanAgent(self.config, self.scope, self.graph, self.audit)
            scan_report = await scan_agent.run(anonymous, sessions)
            scan_data = scan_report.to_dict()
            errors.extend(scan_report.errors)
            log.info(
                "scan: %d pages, %d endpoints, %d identities",
                scan_report.pages,
                scan_report.endpoints,
                scan_report.identities,
            )

            ctx = CheckContext(
                config=self.config,
                graph=self.graph,
                scope=self.scope,
                sessions=sessions,
                anonymous=anonymous,
                audit=self.audit,
            )
            runner = ActionRunner(self.graph, checks, ctx, self.audit)
            identities = list(sessions)

            if self.config.run.max_baseline_actions > 0 and budget.remaining_requests > 0:
                actions = build_check_actions(
                    self.graph.endpoints(),
                    checks,
                    self.config,
                    identities,
                    self.graph.actions_run(),
                )
                baseline = baseline_order(actions, self.config.run.max_baseline_actions)
                log.info(
                    "baseline: %d of %d candidate actions selected",
                    len(baseline),
                    len(actions),
                )
                managed = ManagedAgent(runner, self.config.run.workers)
                phase = await managed.run(baseline, "baseline")
                errors.extend(phase.errors)
                self.audit.record(
                    "phase",
                    name="baseline",
                    actions=phase.actions,
                    validated=len(phase.findings),
                    rejected=phase.rejected,
                )

            if (
                not self.no_explore
                and self.config.run.max_explore_actions > 0
                and budget.remaining_requests > 0
            ):
                remaining = build_check_actions(
                    self.graph.endpoints(),
                    checks,
                    self.config,
                    identities,
                    self.graph.actions_run(),
                )
                planner = MctsPlanner(
                    checks,
                    self.graph.action_stats(),
                    simulations=96,
                    depth=3,
                    seed=17,
                )
                explorer = ExplorationAgent(
                    self.config,
                    self.graph,
                    self.scope,
                    ctx,
                    checks,
                    runner,
                    planner,
                    llm,
                    self.audit,
                    identities,
                )
                log.info("exploration: %d untried check actions", len(remaining))
                phase = await explorer.run(
                    self.config.run.max_explore_actions,
                    self.config.run.stagnant_limit,
                )
                errors.extend(phase.errors)
                self.audit.record(
                    "phase",
                    name="explore",
                    actions=phase.actions,
                    validated=len(phase.findings),
                    rejected=phase.rejected,
                    llm_calls=getattr(llm, "calls", 0),
                )

            await self._finish_candidates(runner, checks)
        except (BudgetExceeded, RunStopped) as exc:
            stopped_reason = str(exc)
            log.warning("run stopped: %s", stopped_reason)
            self.audit.record("stop", reason=stopped_reason)
        except (ConfigError, ScopeError):
            raise
        except Exception as exc:  # keep the partial report, then re-raise
            fatal = exc
            errors.append(f"{type(exc).__name__}: {exc}")
            log.exception("unhandled run error")
        finally:
            llm_calls = int(getattr(llm, "calls", 0))
            await llm.close()
            for session in all_sessions:
                try:
                    await session.close()
                except Exception:
                    pass
            finished_at = utcnow()
            report: dict[str, Any] = {}
            artifacts: dict[str, Path] = {}
            try:
                assert self.graph is not None and self.audit is not None
                report = build_report(
                    self.graph,
                    self.config,
                    run_id=run_id,
                    run_dir=self.run_dir,
                    started_at=started_at,
                    finished_at=finished_at,
                    budget=budget.summary(),
                    scan=scan_data,
                    auth=auth_results,
                    errors=errors,
                    llm_calls=llm_calls,
                    stopped_reason=stopped_reason or budget.stopped_reason,
                )
                artifacts = write_reports(self.run_dir, report, self.graph)
                self.audit.record(
                    "run_finished",
                    findings=report["summary"]["validated"],
                    requests=budget.requests,
                    stopped_reason=report["run"]["stopped_reason"],
                )
            finally:
                self.audit.close()
                self.graph.close()
                self._detach_log()

        if fatal is not None:
            raise fatal
        return RunOutcome(
            run_dir=self.run_dir,
            report=report,
            artifacts=artifacts,
            errors=errors,
        )

    async def _finish_candidates(self, runner: ActionRunner, checks: dict[str, Any]) -> None:
        if self.graph is None:
            return
        for finding in self.graph.findings(Status.CANDIDATE):
            check = checks.get(finding.check_id)
            if check is None:
                continue
            await runner.verify_finding(check, finding)

    def _attach_log(self) -> None:
        assert self.run_dir is not None
        logger = logging.getLogger("redthread")
        if logger.level == logging.NOTSET:
            logger.setLevel(logging.INFO)
        handler = logging.FileHandler(self.run_dir / "redthread.log", encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logger.addHandler(handler)
        self._log_handler = handler

    def _detach_log(self) -> None:
        if not self._log_handler:
            return
        logger = logging.getLogger("redthread")
        logger.removeHandler(self._log_handler)
        self._log_handler.close()
        self._log_handler = None
