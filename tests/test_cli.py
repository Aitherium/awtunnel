"""Test CLI subcommands and exit codes."""

import json
import tempfile
from pathlib import Path

import pytest

from awtunnel.cli import main


def test_validate_success(tmp_path):
    """Validate subcommand exits 0 on valid rules."""
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(json.dumps([
        {"hostname": "localhost", "path": "^/v1", "origin": "http://localhost:8080"},
    ]))

    # Capture stdout/stderr isn't straightforward in this test, but we check exit code
    result = main([
        "validate",
        str(rules_file),
    ])
    assert result == 0


def test_validate_failure(tmp_path):
    """Validate subcommand exits 1 on invalid rules."""
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(json.dumps([
        {"hostname": "api.example.com", "path": "^/", "origin": "http://gateway:8080"},
        {"hostname": "api.example.com", "path": "^/v1", "origin": "https://gateway:8080"},
    ]))

    result = main([
        "validate",
        str(rules_file),
    ])
    assert result == 1  # Scheme conflict detected


def test_validate_missing_file():
    """Validate exits 2 when file is not found."""
    result = main([
        "validate",
        "/nonexistent/path/rules.json",
    ])
    assert result == 2


def test_check_found(tmp_path):
    """Check subcommand exits 0 when rule is found."""
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(json.dumps([
        {"hostname": "api.example.com", "path": "^/v1", "origin": "http://gateway:8080"},
    ]))

    result = main([
        "check",
        str(rules_file),
        "api.example.com",
        "^/v1",
    ])
    assert result == 0


def test_check_not_found(tmp_path):
    """Check subcommand exits 1 when rule is not found."""
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(json.dumps([
        {"hostname": "api.example.com", "path": "^/v1", "origin": "http://gateway:8080"},
    ]))

    result = main([
        "check",
        str(rules_file),
        "api.example.com",
        "^/v2",
    ])
    assert result == 1


def test_check_missing_file():
    """Check exits 2 when file is not found."""
    result = main([
        "check",
        "/nonexistent/path/rules.json",
        "api.example.com",
        "^/v1",
    ])
    assert result == 2


def test_main_no_args():
    """Main with no arguments exits with error."""
    # This should error because required positional argument is missing.
    with pytest.raises(SystemExit):
        main([])


def test_validate_json_output(tmp_path, capsys):
    """Validate can output JSON format."""
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(json.dumps([
        {"hostname": "api.example.com", "path": "^/", "origin": "http://gateway:8080"},
        {"hostname": "api.example.com", "path": "^/v1", "origin": "https://gateway:8080"},
    ]))

    result = main([
        "validate",
        str(rules_file),
        "--json",
    ])
    assert result == 1  # Should have findings
