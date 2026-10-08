import os
import shutil
import socket
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "pg_check.py")

PG_HOST = os.environ.get("PG_CHECK_HOST", "localhost")
PG_PORT = int(os.environ.get("PG_CHECK_PORT", "55432"))
PG_DB = os.environ.get("PG_CHECK_DB", "testdb")
PG_USER = os.environ.get("PG_CHECK_USER", "testuser")
PG_PASSWORD = os.environ.get("PG_CHECK_PASSWORD", "testpass")


def run(*args, script=SCRIPT, cwd=None):
    return subprocess.run([sys.executable, script, *args], capture_output=True,
                          text=True, cwd=cwd, timeout=60)


def db_args(**overrides):
    values = dict(host=PG_HOST, port=str(PG_PORT), database=PG_DB, user=PG_USER,
                  password=PG_PASSWORD)
    values.update(overrides)
    return [item for key, value in values.items() for item in ("--" + key, value)]


def db_available():
    try:
        with socket.create_connection((PG_HOST, PG_PORT), timeout=2):
            return True
    except OSError:
        return False


requires_db = pytest.mark.skipif(not db_available(), reason="PostgreSQL test server not reachable")


def test_help():
    result = run("--help")
    assert result.returncode == 0
    for option in ("--host", "--port", "--database", "--user", "--password",
                   "--timeout", "--ssl", "--ssl-ca-file"):
        assert option in result.stdout


def test_no_arguments_shows_usage():
    result = run()
    assert result.returncode == 0
    assert "usage:" in result.stdout
    assert "CONNECTION CHECK" not in result.stdout


@pytest.mark.parametrize("bad_args", [
    ["--port", "0"], ["--port", "70000"], ["--port", "abc"], ["--timeout", "0"],
    ["--host", ""], ["--ssl-ca-file", "/nonexistent/ca.pem"],
    ["--ssl", "--ssl-ca-file", "/nonexistent/ca.pem"],
])
def test_invalid_arguments_exit_2(bad_args):
    assert run(*bad_args, "--password", "x").returncode == 2


def test_missing_libs_exit_2(tmp_path):
    script = tmp_path / "pg_check.py"
    shutil.copy(SCRIPT, script)
    result = run("--password", "x", script=str(script))
    assert result.returncode == 2
    assert "src" in result.stderr and "ERROR" in result.stderr


def test_empty_libs_does_not_fall_back_to_global(tmp_path):
    script = tmp_path / "pg_check.py"
    shutil.copy(SCRIPT, script)
    (tmp_path / "src" / "libs").mkdir(parents=True)
    result = run("--password", "x", script=str(script))
    assert result.returncode == 2
    assert "pg8000" in result.stderr


def test_missing_dependency_exit_2(tmp_path):
    script = tmp_path / "pg_check.py"
    shutil.copy(SCRIPT, script)
    libs = tmp_path / "src" / "libs"
    shutil.copytree(os.path.join(ROOT, "src", "libs", "pg8000"), libs / "pg8000")
    result = run("--password", "x", script=str(script))
    assert result.returncode == 2
    assert "scramp" in result.stderr or "dateutil" in result.stderr


def test_libs_loaded_from_local_dir():
    code = (
        "import sys; sys.path.insert(0, %r); import pg_check; "
        "d = pg_check.load_pg8000(); "
        "import pg8000, scramp, asn1crypto, dateutil; "
        "print(pg8000.__file__, scramp.__file__, asn1crypto.__file__, dateutil.__file__)"
    ) % ROOT
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd="/")
    assert result.returncode == 0, result.stderr
    libs = os.path.realpath(os.path.join(ROOT, "src", "libs"))
    for path in result.stdout.split():
        assert os.path.realpath(path).startswith(libs)


@requires_db
def test_success_from_other_cwd(tmp_path):
    result = run(*db_args(), cwd=str(tmp_path))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "RESULT: SUCCESS" in result.stdout
    assert "Database connection closed." in result.stdout
    assert PG_DB in result.stdout and "PostgreSQL" in result.stdout
    assert PG_PASSWORD not in result.stdout + result.stderr


@requires_db
def test_wrong_password_exit_1_and_hidden():
    result = run(*db_args(password="wrongsecret123"))
    assert result.returncode == 1
    assert "FAILED" in result.stdout
    assert "wrongsecret123" not in result.stdout + result.stderr


@requires_db
def test_database_not_found_exit_1():
    result = run(*db_args(database="no_such_db"))
    assert result.returncode == 1
    assert "no_such_db" in result.stdout


@requires_db
def test_ssl_against_non_ssl_server_exit_1():
    result = run(*db_args(), "--ssl")
    assert result.returncode == 1
    assert "SSL" in result.stdout


def test_connection_refused_exit_1():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        free_port = sock.getsockname()[1]
    result = run(*db_args(host="127.0.0.1", port=str(free_port)))
    assert result.returncode == 1
    assert "refused" in result.stdout.lower()


def test_dns_failure_exit_1():
    result = run(*db_args(host="no-such-host.invalid"), "--timeout", "5")
    assert result.returncode == 1
    assert "FAILED" in result.stdout
