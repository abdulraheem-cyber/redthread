from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time

from redthread import __version__
from redthread.benchmark import evaluate_run, load_truth
from redthread.checks import all_checks, enabled_checks
from redthread.config import load_config, write_example_config
from redthread.errors import ConfigError, RedthreadError
from redthread.models import Severity
from redthread.neo4j_export import export_graph, graph_path_for_run
from redthread.orchestrator import Orchestrator, RunOutcome
from redthread.scope import Scope

log = logging.getLogger("redthread.cli")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redthread",
        description="Scope-aware exposure validation for web apps and APIs.",
    )
    parser.add_argument("--version", action="version", version=f"redthread {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="execute one validation run")
    _run_options(run, fail_on=True)
    run.add_argument("--json", action="store_true", help="print the run summary as JSON")

    watch = sub.add_parser("watch", help="run repeatedly on a schedule")
    _run_options(watch, fail_on=False)
    watch.add_argument("--interval", type=float, default=3600.0, help="seconds between runs")
    watch.add_argument("--max-runs", type=int, default=0, help="stop after N runs (0 = forever)")

    validate = sub.add_parser("validate", help="parse the config and print the effective scope")
    validate.add_argument("-c", "--config", default="redthread.toml", help="TOML config file")

    init = sub.add_parser("init", help="write a starter config")
    init.add_argument("path", nargs="?", default="redthread.toml")
    init.add_argument("--force", action="store_true")

    sub.add_parser("checks", help="list registered checks")

    evaluate = sub.add_parser("eval", help="score a run against a ground-truth file")
    evaluate.add_argument("--run", default=".", help="run directory containing findings.json")
    evaluate.add_argument("--truth", required=True, help="ground-truth JSON file")
    evaluate.add_argument("--json", action="store_true", help="print machine-readable metrics")
    evaluate.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 when a finding is missing or an unexpected finding was reported",
    )

    export = sub.add_parser("export-neo4j", help="load a run graph into Neo4j")
    export.add_argument("--run", required=True, help="run directory containing graph.json")
    export.add_argument("-c", "--config", help="config file with [graph] neo4j settings")
    export.add_argument("--uri", default="", help="neo4j:// or bolt:// URI")
    export.add_argument("--user", default="")
    export.add_argument("--password", default="")
    export.add_argument("--database", default="")
    return parser


def _run_options(parser: argparse.ArgumentParser, *, fail_on: bool) -> None:
    parser.add_argument("-c", "--config", default="redthread.toml", help="TOML config file")
    parser.add_argument("--no-llm", action="store_true", help="ignore llm settings")
    parser.add_argument("--no-explore", action="store_true", help="baseline checks only")
    parser.add_argument("-q", "--quiet", action="store_true", help="only log warnings and errors")
    if fail_on:
        parser.add_argument(
            "--fail-on",
            choices=["none", "low", "medium", "high", "critical"],
            default="none",
            help="exit non-zero when a validated finding reaches this severity",
        )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "init":
            return _init(args)
        if args.command == "checks":
            return _checks()
        if args.command == "validate":
            return _validate(args)
        if args.command == "eval":
            return _evaluate(args)
        if args.command == "export-neo4j":
            return _export_neo4j(args)
        if args.command == "run":
            return _run(args)
        if args.command == "watch":
            return _watch(args)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    except RedthreadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    return 1


def _init(args: argparse.Namespace) -> int:
    target = write_example_config(args.path, force=args.force)
    print(f"wrote {target}")
    print("review scope.include and identities before running")
    return 0


def _checks() -> int:
    for check in all_checks().values():
        print(f"{check.id:<24} {check.severity.value:<8} {check.title}")
    return 0


def _validate(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    scope = Scope(config)
    try:
        selected = list(enabled_checks(config).values())
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    print(f"config: {config.source}")
    print(f"targets: {', '.join(scope.seeds)}")
    print(f"methods: {', '.join(sorted(scope.methods))}")
    print(f"excludes: {', '.join(config.scope.exclude) or '(none)'}")
    print(f"identities: {', '.join(item.name for item in config.identities) or '(anonymous only)'}")
    print(f"checks: {', '.join(item.id for item in selected) or '(none enabled)'}")
    non_local = config.non_local_seeds()
    if non_local and not config.run.authorized:
        print("note: non-local targets require run.authorized = true before a run")
    return 0


def _logging(args: argparse.Namespace) -> None:
    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def _run(args: argparse.Namespace) -> int:
    _logging(args)
    config = load_config(args.config)
    outcome = asyncio.run(
        Orchestrator(config, no_llm=args.no_llm, no_explore=args.no_explore).run()
    )
    if args.json:
        print(json.dumps(_summary(outcome), indent=2, ensure_ascii=False))
    else:
        _print_outcome(outcome)
    return _exit_code(outcome, args.fail_on)


def _watch(args: argparse.Namespace) -> int:
    _logging(args)
    if args.interval < 1:
        raise RedthreadError("--interval must be at least 1 second")
    if args.max_runs < 0:
        raise RedthreadError("--max-runs cannot be negative")
    config = load_config(args.config)
    completed = 0
    while True:
        outcome = asyncio.run(
            Orchestrator(config, no_llm=args.no_llm, no_explore=args.no_explore).run()
        )
        _print_outcome(outcome)
        completed += 1
        if args.max_runs and completed >= args.max_runs:
            break
        print(f"next run in {args.interval:.0f}s")
        try:
            time.sleep(args.interval)
        except KeyboardInterrupt:
            break
    return 0


def _evaluate(args: argparse.Namespace) -> int:
    truth = load_truth(args.truth)
    result = evaluate_run(args.run, truth)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"benchmark: {result['suite'] or '(unnamed)'}")
        print(f"run: {result['run']}")
        print(
            f"expected {result['expected']}, matched {result['satisfied']}, "
            f"precision {result['precision']:.3f}, recall {result['recall']:.3f}, "
            f"f1 {result['f1']:.3f}"
        )
        if result["missing"]:
            print("missing:")
            for item in result["missing"]:
                target = item.get("path") or item.get("path_contains") or "(any endpoint)"
                parameter = f" [{item['parameter']}]" if item.get("parameter") else ""
                print(f"  {item['check_id']}{parameter} {target}")
        if result["unexpected"]:
            print("unexpected:")
            for item in result["unexpected"]:
                print(
                    f"  {item['check_id']} {item['endpoint']}"
                    + (f" [{item['parameter']}]" if item.get("parameter") else "")
                )
    if args.strict and (result["missing"] or result["unexpected"]):
        return 1
    return 0


def _export_neo4j(args: argparse.Namespace) -> int:
    config = load_config(args.config) if args.config else None
    uri = args.uri or (config.graph.neo4j_uri if config else "")
    if not uri:
        raise RedthreadError("provide --uri or set graph.neo4j_uri in the config")
    user = args.user or (config.graph.neo4j_user if config else "")
    password = args.password or (config.graph.neo4j_password if config else "")
    database = args.database or (config.graph.neo4j_database if config else "neo4j")
    counts = export_graph(
        graph_path_for_run(args.run),
        uri=uri,
        user=user,
        password=password,
        database=database,
    )
    print(
        f"exported {counts['nodes']} nodes, {counts['edges']} edges and "
        f"{counts['findings']} findings"
    )
    return 0


def _summary(outcome: RunOutcome) -> dict:
    report = outcome.report
    return {
        "run": report.get("run", {}).get("id"),
        "directory": str(outcome.run_dir),
        "validated": report.get("summary", {}).get("validated", 0),
        "rejected": report.get("summary", {}).get("rejected", 0),
        "by_severity": report.get("summary", {}).get("by_severity", {}),
        "findings": [
            {
                "id": item.get("display_id"),
                "check": item.get("check_id"),
                "severity": item.get("severity"),
                "endpoint": item.get("endpoint"),
                "parameter": item.get("parameter"),
            }
            for item in report.get("findings", [])
        ],
    }


def _print_outcome(outcome: RunOutcome) -> None:
    report = outcome.report
    summary = report.get("summary", {})
    print(f"run directory: {outcome.run_dir}")
    counts = summary.get("by_severity", {})
    counted = ", ".join(f"{name} {count}" for name, count in counts.items() if count)
    print(
        f"validated: {summary.get('validated', 0)}"
        + (f" ({counted})" if counted else "")
        + f", rejected: {summary.get('rejected', 0)}"
        + f", requests: {summary.get('requests', 0)}"
    )
    for item in report.get("findings", []):
        parameter = f" [{item['parameter']}]" if item.get("parameter") else ""
        print(
            f"  {item.get('display_id', '')} {item.get('severity', ''):<8} "
            f"{item.get('check_id', '')}{parameter} "
            f"{item.get('method', '')} {item.get('endpoint', '')}"
        )
    if report.get("run", {}).get("stopped_reason"):
        print(f"stopped: {report['run']['stopped_reason']}")
    if outcome.errors:
        print(f"warnings: {len(outcome.errors)} (see run.json)")
    print(f"report: {outcome.artifacts.get('report', outcome.run_dir / 'report.md')}")


def _exit_code(outcome: RunOutcome, fail_on: str) -> int:
    if fail_on == "none":
        return 0
    threshold = Severity(fail_on).rank
    for item in outcome.report.get("findings", []):
        if Severity(item["severity"]).rank >= threshold:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
