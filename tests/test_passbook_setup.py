# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Setup tests — the first-run path, which is the one nobody gets to retry.

`cryptography` is not in the standard library and cannot be installed into a
system Python on most machines: Homebrew, Debian and Ubuntu all mark theirs
externally managed and refuse (PEP 668). So "run pip install" is not a fallback,
it is a dead end, and setup has to provision its own interpreter instead.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

# `install.sh` and the command shims are POSIX shell scripts. Windows cannot
# execute them at all: it answers "%1 is not a valid Win32 application". What
# they check is real and is checked on the platforms that can run them.
needs_a_posix_shell = pytest.mark.skipif(
    os.name == "nt", reason="install.sh and the shims are POSIX shell")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import passbook  # noqa: E402
import passbook_cli  # noqa: E402

PACKAGE = Path(__file__).resolve().parents[1]
INSTALLER = PACKAGE / "install.sh"


@pytest.fixture
def machine(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "hive"))
    monkeypatch.delenv("APP_SANDBOX_CONTAINER_ID", raising=False)
    monkeypatch.delenv("HIVE_WORKSPACE", raising=False)
    return tmp_path


def _install(prefix: Path, *extra: str, home: Path, env: dict | None = None):
    return subprocess.run(
        [sys.executable, "-m", "passbook_cli", "install", "--prefix", str(prefix), *extra],
        capture_output=True, text=True, cwd=str(PACKAGE),
        env={**os.environ, "HIVE_HOME": str(home), "PYTHONPATH": str(PACKAGE), **(env or {})},
    )


# ── the commands land and work ─────────────────────────────────────────────


def test_setup_installs_every_command_and_provisions_the_store(machine):
    prefix = machine / "bin"
    home = machine / "hive"

    done = _install(prefix, "--no-runtime", home=home)

    assert done.returncode == 0, done.stderr
    installed = sorted(item.name for item in prefix.iterdir())
    assert installed == sorted(["passbook", *passbook_cli.aliases()])
    assert (home / ".env").is_file(), "setup must leave a usable store behind"


@needs_a_posix_shell
def test_an_installed_command_runs_and_reads_the_store(machine):
    prefix = machine / "bin"
    home = machine / "hive"
    _install(prefix, "--no-runtime", home=home)

    subprocess.run([str(prefix / "passbook-add"), "SETUP_KEY=value"],
                   env={**os.environ, "HIVE_HOME": str(home)}, check=True, capture_output=True)
    done = subprocess.run([str(prefix / "passbook-check"), "SETUP_KEY"],
                          env={**os.environ, "HIVE_HOME": str(home)}, capture_output=True, text=True)

    assert done.returncode == 0
    assert "SETUP_KEY: set" in done.stdout


@needs_a_posix_shell
def test_a_shim_dispatches_on_its_own_name_not_the_script_path(machine):
    """argv[0] is the script, so the shim has to name itself explicitly."""
    prefix = machine / "bin"
    home = machine / "hive"
    _install(prefix, "--no-runtime", home=home)

    body = (prefix / "passbook-list").read_text(encoding="utf-8")
    assert 'PASSBOOK_INVOKED_AS="${0##*/}"' in body

    done = subprocess.run([str(prefix / "passbook-list")],
                          env={**os.environ, "HIVE_HOME": str(home)}, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


def test_setup_is_idempotent(machine):
    prefix = machine / "bin"
    home = machine / "hive"
    _install(prefix, "--no-runtime", home=home)
    before = (prefix / "passbook").read_text(encoding="utf-8")

    second = _install(prefix, "--no-runtime", home=home)

    assert second.returncode == 0
    assert (prefix / "passbook").read_text(encoding="utf-8") == before


def test_setup_refuses_to_overwrite_something_that_is_not_ours(machine):
    """A stray `passbook` on PATH belongs to the user, not to this installer."""
    prefix = machine / "bin"
    prefix.mkdir()
    stranger = prefix / "passbook"
    stranger.write_text("#!/bin/sh\necho not ours\n", encoding="utf-8")

    done = _install(prefix, "--no-runtime", home=machine / "hive")

    assert "skipped (not ours)" in done.stdout
    assert stranger.read_text(encoding="utf-8") == "#!/bin/sh\necho not ours\n"


# ── the runtime ────────────────────────────────────────────────────────────


def test_a_python_that_already_has_crypto_is_used_as_is(machine):
    """No point provisioning anything when the interpreter is already fine."""
    interpreter, why = passbook_cli.resolve_interpreter(provision=False)
    if not passbook_cli._has_crypto(sys.executable):
        pytest.skip("this interpreter has no cryptography")
    assert interpreter == sys.executable
    assert "already has everything" in why


@pytest.fixture
def crypto_free_python(tmp_path):
    """A real interpreter with no `cryptography`, standing in for a fresh machine.

    The suite itself runs under an interpreter that has it, so without this the
    degraded path would never actually be exercised — which is exactly the path
    a first-time user is on.
    """
    venv = tmp_path / "bare"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)],
                   check=True, capture_output=True)
    interpreter = venv / "bin" / "python"
    if not interpreter.exists() or passbook_cli._has_crypto(interpreter):
        pytest.skip("could not build an interpreter without cryptography")
    return interpreter


def test_setup_reports_honestly_when_the_runtime_is_missing(machine, crypto_free_python):
    """Degrading is fine. Degrading silently is not — seal and link would fail later."""
    done = subprocess.run(
        [str(crypto_free_python), "-m", "passbook_cli", "install",
         "--prefix", str(machine / "bin"), "--no-runtime"],
        capture_output=True, text=True, cwd=str(PACKAGE),
        env={**os.environ, "HIVE_HOME": str(machine / "hive"), "PYTHONPATH": str(PACKAGE)},
    )

    assert done.returncode == 0, done.stderr
    assert "sealing and linking: UNAVAILABLE" in done.stdout
    assert "Everything else works" in done.stdout
    assert "pip install" not in done.stdout + done.stderr


def test_setup_provisions_a_runtime_when_the_interpreter_lacks_one(machine, crypto_free_python):
    """The whole point: a machine that cannot pip-install still ends up working."""
    done = subprocess.run(
        [str(crypto_free_python), "-m", "passbook_cli", "install", "--prefix", str(machine / "bin")],
        capture_output=True, text=True, cwd=str(PACKAGE),
        env={**os.environ, "HIVE_HOME": str(machine / "hive"), "PYTHONPATH": str(PACKAGE)},
    )

    if "sealing and linking: ready" not in done.stdout:
        pytest.skip(f"no network or build tools for provisioning: {done.stdout[-300:]}")
    runtime = machine / "hive" / "passbook-runtime"
    assert runtime.is_dir(), "the runtime must live beside the store"
    assert str(runtime) in (machine / "bin" / "passbook-link").read_text(encoding="utf-8")

    linked = subprocess.run([str(machine / "bin" / "passbook-link")],
                            env={**os.environ, "HIVE_HOME": str(machine / "hive")},
                            capture_output=True, text=True)
    assert linked.returncode == 0, linked.stderr
    assert "fingerprint:" in linked.stdout, "linking must work right after setup"


def test_setup_never_tells_anyone_to_pip_install_into_their_system_python(machine):
    """That advice is refused outright by Homebrew, Debian and Ubuntu (PEP 668).

    Failing with an error about the operating system, for a command we suggested,
    is worse than not suggesting it.
    """
    done = _install(machine / "bin", "--no-runtime", home=machine / "hive")
    assert "pip install" not in done.stdout + done.stderr

    seal = subprocess.run(
        [sys.executable, "-m", "passbook_cli", "link"], capture_output=True, text=True, cwd=str(PACKAGE),
        env={k: v for k, v in os.environ.items() if k != "PATH"}
        | {"HIVE_HOME": str(machine / "hive"), "PYTHONPATH": str(PACKAGE), "PATH": "/nonexistent"},
    )
    assert "pip install" not in seal.stdout + seal.stderr


def test_the_runtime_lives_beside_the_store_not_inside_the_project(machine):
    assert passbook_cli.runtime_root() == passbook.root() / "passbook-runtime"
    assert passbook_cli.runtime_root().parent == passbook.root()


# ── the shell bootstrap ────────────────────────────────────────────────────


@pytest.mark.skipif(not INSTALLER.is_file(), reason="installer is not present")
@needs_a_posix_shell
def test_the_installer_stops_cleanly_when_no_python_is_usable(machine):
    """Half-installing and letting someone discover it later is the failure mode."""
    done = subprocess.run(
        ["/bin/sh", str(INSTALLER), "--prefix", str(machine / "bin")],
        capture_output=True, text=True,
        env={"HOME": str(machine), "HIVE_HOME": str(machine / "hive"),
             "PATH": "/nonexistent", "PASSBOOK_PYTHON": ""},
    )

    assert done.returncode == 1
    assert "needs Python" in done.stderr
    assert not (machine / "bin").exists(), "nothing should be left behind"


@pytest.mark.skipif(not INSTALLER.is_file(), reason="installer is not present")
@needs_a_posix_shell
def test_the_installer_honours_an_explicit_interpreter(machine):
    done = subprocess.run(
        ["/bin/sh", str(INSTALLER), "--prefix", str(machine / "bin"), "--no-runtime"],
        capture_output=True, text=True,
        env={**os.environ, "HIVE_HOME": str(machine / "hive"), "PASSBOOK_PYTHON": sys.executable},
    )

    assert done.returncode == 0, done.stderr
    assert sys.executable in done.stdout
    assert (machine / "bin" / "passbook-check").is_file()


def test_every_module_in_the_repo_is_declared_for_install():
    """A module missing from pyproject is a module the installed CLI lacks.

    The install copies the declared list, so an omission is invisible from
    inside the checkout — the working tree shadows site-packages and every
    check passes locally while the installed command runs older code. That is
    not hypothetical: `passbook_backup` added export, import and recovery and
    was never declared, so no installed copy could reach any of it, and
    `passbook_stamp` sat at a stale revision while the tree it was tested from
    looked correct.
    """
    # `tomllib` is standard from 3.11. This project supports 3.9, where the
    # only ways to read a TOML file are a dependency the test suite does not
    # have or a parser written here. Both are worse than checking on the
    # interpreters that can: what this asserts is a fact about the repository,
    # not about the Python running it, so proving it once is proving it.
    tomllib = pytest.importorskip(
        "tomllib", reason="reading pyproject needs tomllib, standard from 3.11")

    repo = Path(__file__).resolve().parents[1]
    declared = set(
        tomllib.loads((repo / "pyproject.toml").read_text(encoding="utf-8"))
        ["tool"]["setuptools"]["py-modules"]
    )
    on_disk = {
        path.stem for path in repo.glob("passbook*.py")
        if not path.stem.endswith("_test")
    }
    missing = on_disk - declared
    stale = declared - on_disk
    assert not missing, f"modules in the repo but not installed: {sorted(missing)}"
    assert not stale, f"modules declared but absent from the repo: {sorted(stale)}"


def test_every_verb_is_also_a_hyphenated_command():
    """`--help` promises every subcommand hyphenated. Two lists have to agree.

    `passbook install` writes a shim per verb, derived from the parser, so it
    is always complete. `pip install` and `uv tool install` read the hand-kept
    list in pyproject, which drifted: nine verbs including `sync`, `export` and
    `recovery` had no console script, so `passbook-sync` existed for anyone who
    ran the installer and did not exist for anyone who used pip.
    """
    # `tomllib` is standard from 3.11. This project supports 3.9, where the
    # only ways to read a TOML file are a dependency the test suite does not
    # have or a parser written here. Both are worse than checking on the
    # interpreters that can: what this asserts is a fact about the repository,
    # not about the Python running it, so proving it once is proving it.
    tomllib = pytest.importorskip(
        "tomllib", reason="reading pyproject needs tomllib, standard from 3.11")

    repo = Path(__file__).resolve().parents[1]
    declared = set(
        tomllib.loads((repo / "pyproject.toml").read_text(encoding="utf-8"))["project"]["scripts"]
    ) - {"passbook"}
    derived = set(passbook_cli.aliases())
    missing = derived - declared
    stale = declared - derived
    assert not missing, f"verbs with no console script: {sorted(missing)}"
    assert not stale, f"console scripts for verbs that do not exist: {sorted(stale)}"
