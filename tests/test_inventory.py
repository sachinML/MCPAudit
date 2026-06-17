"""Tests for config inventory and cross-server analysis."""

from __future__ import annotations

import json
from pathlib import Path

from mcts.analyzers.cross_server import CrossServerAnalyzer
from mcts.inventory.discoverers import parse_config_file
from mcts.inventory.models import InventoryEntry
from mcts.taxonomy.mapper import enrich_findings, load_taxonomy


def test_parse_cursor_config(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "alpha": {"command": "uv", "args": ["run", "server.py"]},
                    "beta": {"command": "uv", "args": ["run", "server.py"]},
                }
            }
        )
    )
    entries = parse_config_file("cursor", config)
    assert len(entries) == 2
    assert entries[0].server_name in {"alpha", "beta"}


def test_cross_server_detects_name_collision() -> None:
    inventory = [
        InventoryEntry(client="cursor", config_path="/a", server_name="s1", tools=["read_file"]),
        InventoryEntry(client="claude", config_path="/b", server_name="s2", tools=["read_file"]),
    ]
    findings = CrossServerAnalyzer(inventory).analyze_inventory(inventory)
    assert findings
    assert findings[0].technique_id == "MCTS-T-1008"


def test_taxonomy_enriches_findings() -> None:
    from mcts.reporting.models import Finding, Severity

    finding = Finding(
        id="x",
        analyzer="command_execution",
        title="t",
        description="d",
        severity=Severity.CRITICAL,
        recommendation="r",
    )
    enriched = enrich_findings([finding])[0]
    assert enriched.technique_id == "MCTS-T-1003"
    assert enriched.cwe_id == "CWE-78"
    assert enriched.mitigation_ids


def test_taxonomy_catalog_loads() -> None:
    data = load_taxonomy()
    assert "MCTS-T-1001" in data["techniques"]
    assert data["mitigations"]


def test_redact_home() -> None:
    from mcts.inventory.discoverers import redact_home

    home = str(Path.home())
    assert redact_home(f"{home}/.cursor/mcp.json") == "~/.cursor/mcp.json"
    assert redact_home("/other/path") == "/other/path"


def test_path_only_returns_tuples(tmp_path: Path) -> None:
    from mcts.inventory.discoverers import discover_config_paths

    rows = discover_config_paths()
    for client, path in rows:
        assert isinstance(client, str)
        assert isinstance(path, Path)


def test_config_path_scopes_to_single_file(tmp_path: Path) -> None:
    config = tmp_path / "custom.json"
    config.write_text(json.dumps({"mcpServers": {"myserver": {"command": "node", "args": ["sever.js"]}}}))
    from mcts.inventory.runner import run_inventory

    report = run_inventory(config_path=config)
    assert len(report.entries) == 1
    assert report.entries[0].server_name == "myserver"
    assert report.clients_scanned == ["user"]


def test_config_path_missing_file_returns_empty(tmp_path: Path) -> None:
    from mcts.inventory.runner import run_inventory

    report = run_inventory(config_path=tmp_path / "nope.json")
    assert len(report.entries) == 0
