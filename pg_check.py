#!/usr/bin/env python3
"""Standalone PostgreSQL connection checker using the bundled pg8000 in src/libs."""

import argparse
import getpass
import importlib
import os
import socket
import ssl
import sys
import time

# ======================= CONFIGURATION (edit here) =======================
DB_HOST = "localhost"
DB_PORT = 5432
DB_NAME = "postgres"
DB_USER = "postgres"
DB_PASSWORD = None  # None = prompt interactively
DB_TIMEOUT = 10
DB_SSL = False
DB_SSL_CA_FILE = None
# =========================================================================

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
LIBS_DIR = os.path.join(APP_ROOT, "src", "libs")

# Third-party packages pg8000 may import; each must come from LIBS_DIR if loaded.
THIRD_PARTY_MODULES = ("pg8000", "scramp", "asn1crypto", "dateutil", "six")

QUERY = """
SELECT
    CURRENT_TIMESTAMP AS db_timestamp,
    CURRENT_DATABASE() AS database_name,
    CURRENT_USER AS database_user,
    INET_SERVER_ADDR() AS server_ip,
    INET_SERVER_PORT() AS server_port,
    VERSION() AS postgres_version
"""

SEPARATOR = "=" * 65


def is_inside(path, directory):
    path = os.path.normcase(os.path.realpath(path))
    directory = os.path.normcase(os.path.realpath(directory))
    return path == directory or path.startswith(directory + os.sep)


def load_pg8000():
    """Import pg8000.dbapi using only src/libs for third-party code."""
    if not os.path.isdir(LIBS_DIR):
        raise ImportError("Local library directory not found: %s" % LIBS_DIR)

    # Drop site-packages entries so missing local dependencies cannot be
    # silently satisfied by globally installed packages.
    original_path = list(sys.path)
    sys.path[:] = [LIBS_DIR] + [
        entry for entry in original_path
        if "site-packages" not in entry and "dist-packages" not in entry
        and os.path.normcase(os.path.realpath(entry or ".")) != os.path.normcase(LIBS_DIR)
    ]
    try:
        dbapi = importlib.import_module("pg8000.dbapi")
    except ImportError as error:
        missing = getattr(error, "name", None) or str(error)
        raise ImportError(
            "Cannot import pg8000 or a required dependency from %s (missing: %s)"
            % (LIBS_DIR, missing)
        ) from error
    finally:
        sys.path[:] = original_path
        if LIBS_DIR not in sys.path:
            sys.path.insert(0, LIBS_DIR)

    for name in THIRD_PARTY_MODULES:
        for module_name, module in list(sys.modules.items()):
            if module_name != name and not module_name.startswith(name + "."):
                continue
            module_file = getattr(module, "__file__", None)
            if module_file and not is_inside(module_file, LIBS_DIR):
                raise ImportError(
                    "Module '%s' was loaded from outside src/libs: %s" % (module_name, module_file)
                )
    return dbapi


def parse_arguments():
    parser = argparse.ArgumentParser(description="PostgreSQL connection checker (read-only).")
    parser.add_argument("--host", default=DB_HOST, help="PostgreSQL hostname or IP")
    parser.add_argument("--port", type=int, default=DB_PORT, help="PostgreSQL port")
    parser.add_argument("--database", default=DB_NAME, help="Database name")
    parser.add_argument("--user", default=DB_USER, help="Database username")
    parser.add_argument("--password", default=DB_PASSWORD, help="Database password")
    parser.add_argument("--timeout", type=float, default=DB_TIMEOUT,
                        help="Connection timeout in seconds")
    parser.add_argument("--ssl", action="store_true", default=DB_SSL,
                        help="Enable SSL with certificate verification")
    parser.add_argument("--ssl-ca-file", default=DB_SSL_CA_FILE, help="Optional CA certificate path")
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(EXIT_OK)
    args = parser.parse_args()

    problems = []
    if not args.host or not str(args.host).strip():
        problems.append("host must not be empty")
    if not 1 <= args.port <= 65535:
        problems.append("port must be between 1 and 65535")
    if not args.database:
        problems.append("database must not be empty")
    if not args.user:
        problems.append("user must not be empty")
    if args.timeout <= 0:
        problems.append("timeout must be greater than 0")
    if args.ssl_ca_file:
        if not args.ssl:
            problems.append("--ssl-ca-file requires --ssl")
        elif not os.path.isfile(args.ssl_ca_file):
            problems.append("CA file not found: %s" % args.ssl_ca_file)
    if problems:
        parser.error("; ".join(problems))
    return args


def create_ssl_context(ca_file):
    """Return a context verifying certificate and hostname."""
    context = ssl.create_default_context(cafile=ca_file)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def describe_error(error, password):
    text = "%s: %s" % (type(error).__name__, error)
    if password:
        text = text.replace(password, "********")
    return text


def classify_error(error):
    text = str(error).lower()
    chain = []
    current = error
    while current is not None and len(chain) < 5:
        chain.append(current)
        current = current.__cause__ or current.__context__
    if any(isinstance(item, socket.gaierror) for item in chain) or "name or service not known" in text \
            or "getaddrinfo" in text or "nodename nor servname" in text:
        return "DNS resolution failure"
    if any(isinstance(item, ssl.SSLError) for item in chain) or "ssl" in text or "certificate" in text:
        return "SSL/TLS error"
    if any(isinstance(item, ConnectionRefusedError) for item in chain) or "refused" in text:
        return "Connection refused"
    if any(isinstance(item, (socket.timeout, TimeoutError)) for item in chain) or "timed out" in text:
        return "Connection timeout"
    if "password authentication" in text or "authentication" in text or "28p01" in text or "28000" in text:
        return "Authentication failure"
    if "does not exist" in text and "database" in text or "3d000" in text:
        return "Database not found"
    return None


def check_database(dbapi, args, password):
    """Connect, run the query, print results. Returns True on success."""
    ssl_state = "Enabled (certificate and hostname verification)" if args.ssl else "Disabled"
    if args.ssl and args.ssl_ca_file:
        ssl_state += ", CA file: %s" % args.ssl_ca_file

    print(SEPARATOR)
    print("POSTGRESQL CONNECTION CHECK")
    print(SEPARATOR)
    print()
    print("%-22s: %s" % ("Host", args.host))
    print("%-22s: %s" % ("Port", args.port))
    print("%-22s: %s" % ("Database", args.database))
    print("%-22s: %s" % ("Username", args.user))
    print("%-22s: %s" % ("SSL", ssl_state))
    print("%-22s: %g seconds" % ("Timeout", args.timeout))
    print()
    print("Connecting to PostgreSQL...")
    print()

    connection = None
    cursor = None
    success = False
    stage = "Connection"
    try:
        # In pg8000, ssl_context=None means "no SSL"; only pass it when enabled.
        connect_args = dict(host=args.host, port=args.port, database=args.database,
                            user=args.user, password=password, timeout=args.timeout)
        if args.ssl:
            connect_args["ssl_context"] = create_ssl_context(args.ssl_ca_file)

        started = time.perf_counter()
        connection = dbapi.connect(**connect_args)
        connection_time = time.perf_counter() - started
        print("%-22s: SUCCESS" % "Connection")
        print("%-22s: %.3f seconds" % ("Connection time", connection_time))
        print()
        print("Executing SQL query...")
        print()

        stage = "Query execution"
        cursor = connection.cursor()
        started = time.perf_counter()
        cursor.execute(QUERY)
        row = cursor.fetchone()
        query_time = time.perf_counter() - started

        print(SEPARATOR)
        print("DATABASE DETAILS")
        print(SEPARATOR)
        print()
        labels = ("Database timestamp", "Database name", "Database user",
                  "Server IP", "Server port", "PostgreSQL version")
        for label, value in zip(labels, row):
            print("%-22s: %s" % (label, value))
        print()
        print("%-22s: SUCCESS" % "Query execution")
        print("%-22s: %.3f seconds" % ("Query time", query_time))
        success = True
    except Exception as error:  # report any driver/network/SSL failure
        category = classify_error(error)
        print("%-22s: FAILED" % stage)
        if category:
            print("%-22s: %s" % ("Category", category))
        print("%-22s: %s" % ("Error", describe_error(error, password)))
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except Exception:
                pass
        if connection is not None:
            try:
                connection.close()
                closed = True
            except Exception:
                closed = False

    print()
    print(SEPARATOR)
    print("RESULT: %s" % ("SUCCESS" if success else "FAILED"))
    print(SEPARATOR)
    if connection is not None:
        print()
        print("Database connection closed." if closed else "Warning: failed to close connection cleanly.")
    return success


def main():
    args = parse_arguments()

    try:
        dbapi = load_pg8000()
    except ImportError as error:
        print("ERROR: %s" % error, file=sys.stderr)
        return EXIT_USAGE

    password = args.password
    if password is None:
        try:
            password = getpass.getpass("Password for %s@%s: " % (args.user, args.host))
        except (EOFError, KeyboardInterrupt):
            print("\nERROR: no password provided", file=sys.stderr)
            return EXIT_USAGE

    return EXIT_OK if check_database(dbapi, args, password) else EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())
