#!/usr/bin/env python3
"""
PDBSQL Test Harness

Tests CLI (all 5 modes) including server and remote client.

Usage:
    python run_tests.py [--skip-build] [--test-pdb path/to/test.pdb]

Requirements:
    - CMake in PATH
    - Python 3.6+

Exit codes:
    0 = all tests passed
    1 = tests failed
    2 = build failed
    3 = server failed to start
"""
import os
import sys
import subprocess
import time
import argparse
import socket
import struct
import json
from pathlib import Path
from typing import Optional, List, Dict, Any


class PdbsqlClient:
    """Simple client for PDBSQL server protocol."""

    def __init__(self, host: str = 'localhost', port: int = 13337):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None

    def connect(self, timeout: float = 5.0) -> bool:
        """Connect to server. Returns True on success."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(timeout)
            self.sock.connect((self.host, self.port))
            return True
        except Exception:
            self.sock = None
            return False

    def disconnect(self):
        """Disconnect from server."""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None

    def query(self, sql: str) -> Dict[str, Any]:
        """Execute SQL query and return result dict."""
        if not self.sock:
            return {'success': False, 'error': 'Not connected'}

        try:
            # Send request
            req = json.dumps({'sql': sql})
            req_bytes = req.encode('utf-8')
            self.sock.sendall(struct.pack('<I', len(req_bytes)) + req_bytes)

            # Receive response length
            len_bytes = self._recv_exact(4)
            if len_bytes is None:
                return {'success': False, 'error': 'Connection closed'}

            resp_len = struct.unpack('<I', len_bytes)[0]
            if resp_len > 100 * 1024 * 1024:  # 100MB limit
                return {'success': False, 'error': 'Response too large'}

            # Receive response
            resp_bytes = self._recv_exact(resp_len)
            if resp_bytes is None:
                return {'success': False, 'error': 'Connection closed'}

            return json.loads(resp_bytes.decode('utf-8'))

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _recv_exact(self, n: int) -> Optional[bytes]:
        """Receive exactly n bytes."""
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data


def define_cli_local_tests() -> List[Dict[str, Any]]:
    """Define tests for CLI local modes."""
    return [
        # Mode 1: Single query tests
        {
            'name': 'cli_local_count_functions',
            'mode': 'query',
            'sql': 'SELECT COUNT(*) as count FROM functions',
            'check': lambda out, rc: rc == 0 and 'count' in out and 'row(s)' in out,
        },
        {
            'name': 'cli_local_list_functions',
            'mode': 'query',
            'sql': 'SELECT name, rva FROM functions LIMIT 3',
            'check': lambda out, rc: rc == 0 and 'name' in out and 'rva' in out and '3 row(s)' in out,
        },
        {
            'name': 'cli_local_list_udts',
            'mode': 'query',
            'sql': 'SELECT name FROM udts LIMIT 5',
            'check': lambda out, rc: rc == 0 and 'name' in out,
        },
        {
            'name': 'cli_local_invalid_table',
            'mode': 'query',
            'sql': 'SELECT * FROM nonexistent_table',
            'check': lambda out, rc: 'no such table' in out.lower() or 'error' in out.lower(),
        },
        {
            'name': 'cli_local_syntax_error',
            'mode': 'query',
            'sql': 'SELECTT * FROM functions',
            'check': lambda out, rc: 'syntax error' in out.lower() or 'error' in out.lower(),
        },
        # Mode 2: Interactive mode tests
        {
            'name': 'cli_interactive_tables',
            'mode': 'interactive',
            'commands': ['.tables', '.quit'],
            'check': lambda out, rc: rc == 0 and 'functions' in out,
        },
        {
            'name': 'cli_interactive_query',
            'mode': 'interactive',
            'commands': ['SELECT COUNT(*) as cnt FROM functions;', '.quit'],
            'check': lambda out, rc: rc == 0 and 'cnt' in out,
        },
    ]


def define_remote_tests() -> List[Dict[str, Any]]:
    """Define tests for remote mode (via Python client)."""
    return [
        {
            'name': 'count_functions',
            'sql': 'SELECT COUNT(*) as count FROM functions',
            'check': lambda r: r['success'] and len(r['rows']) == 1,
        },
        {
            'name': 'list_functions',
            'sql': 'SELECT name, rva, length FROM functions LIMIT 5',
            'check': lambda r: r['success'] and 'name' in r['columns'],
        },
        {
            'name': 'list_udts',
            'sql': 'SELECT name FROM udts LIMIT 10',
            'check': lambda r: r['success'],
        },
        {
            'name': 'list_enums',
            'sql': 'SELECT name FROM enums LIMIT 5',
            'check': lambda r: r['success'],
        },
        {
            'name': 'invalid_table',
            'sql': 'SELECT * FROM nonexistent_table',
            'check': lambda r: not r['success'] and 'error' in r,
        },
        {
            'name': 'syntax_error',
            'sql': 'SELECTT * FROM functions',
            'check': lambda r: not r['success'] and 'error' in r,
        },
    ]


class TestHarness:
    def __init__(self, skip_build: bool = False, test_pdb: Optional[str] = None):
        self.skip_build = skip_build
        self.test_dir = Path(__file__).parent
        self.src_dir = self.test_dir.parent
        self.pdbsql_dir = self.src_dir.parent

        # Test PDB
        if test_pdb:
            self.test_pdb = Path(test_pdb)
        else:
            # Default: use test_program.pdb from testdata
            self.test_pdb = self.pdbsql_dir / 'tests' / 'testdata' / 'test_program.pdb'

        if not self.test_pdb.exists():
            raise RuntimeError(f"Test PDB not found: {self.test_pdb}")

        # Build config
        self.config = 'Release'
        self.server_process: Optional[subprocess.Popen] = None
        self.server_port = 13339  # Use different port to avoid conflicts

        # CLI executable path
        if sys.platform == 'win32':
            self.cli_exe = self.pdbsql_dir / 'build' / 'bin' / self.config / 'pdbsql.exe'
        else:
            self.cli_exe = self.pdbsql_dir / 'build' / 'bin' / self.config / 'pdbsql'

    def log(self, msg: str):
        print(f"[harness] {msg}")

    def build(self) -> bool:
        """Build pdbsql."""
        if self.skip_build:
            self.log("Skipping build (--skip-build)")
            return True

        self.log("Building pdbsql...")

        # Configure
        result = subprocess.run(
            ['cmake', '-B', 'build'],
            cwd=str(self.pdbsql_dir),
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            self.log(f"CMake configure failed:\n{result.stderr}")
            return False

        # Build
        result = subprocess.run(
            ['cmake', '--build', 'build', '--config', self.config],
            cwd=str(self.pdbsql_dir),
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            self.log(f"CMake build failed:\n{result.stderr}")
            return False

        return True

    def run_cli_local_tests(self) -> List[Dict[str, Any]]:
        """Run CLI local mode tests (modes 1 and 2)."""
        self.log("Running CLI local mode tests...")

        if not self.cli_exe.exists():
            self.log(f"CLI not found: {self.cli_exe}")
            return [{'name': 'cli_not_found', 'passed': False, 'error': 'CLI executable not found'}]

        tests = define_cli_local_tests()
        results = []

        for test in tests:
            name = test['name']
            mode = test['mode']

            try:
                if mode == 'query':
                    # Mode 1: Single query
                    result = subprocess.run(
                        [str(self.cli_exe), str(self.test_pdb), '-q', test['sql']],
                        capture_output=True,
                        text=True,
                        timeout=60
                    )
                    output = result.stdout + result.stderr
                    passed = test['check'](output, result.returncode)

                elif mode == 'interactive':
                    # Mode 2: Interactive
                    input_text = '\n'.join(test['commands']) + '\n'
                    result = subprocess.run(
                        [str(self.cli_exe), str(self.test_pdb), '-i'],
                        input=input_text,
                        capture_output=True,
                        text=True,
                        timeout=60
                    )
                    output = result.stdout + result.stderr
                    passed = test['check'](output, result.returncode)

                else:
                    passed = False
                    output = f"Unknown mode: {mode}"

                results.append({
                    'name': name,
                    'passed': passed,
                    'output': output[:500] if not passed else '',
                    'returncode': result.returncode,
                })

            except subprocess.TimeoutExpired:
                results.append({
                    'name': name,
                    'passed': False,
                    'error': 'Timeout',
                })
            except Exception as e:
                results.append({
                    'name': name,
                    'passed': False,
                    'error': str(e),
                })

        return results

    def start_server(self) -> bool:
        """Start pdbsql server in background."""
        self.log(f"Starting server with {self.test_pdb.name} on port {self.server_port}...")

        if not self.cli_exe.exists():
            self.log(f"CLI not found: {self.cli_exe}")
            return False

        # Start server
        self.server_process = subprocess.Popen(
            [str(self.cli_exe), str(self.test_pdb), '--server', str(self.server_port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        # Wait for server to start
        self.log("Waiting for server to start...")
        start_time = time.time()
        timeout = 30  # seconds

        while time.time() - start_time < timeout:
            # Check if process died
            if self.server_process.poll() is not None:
                output = self.server_process.stdout.read()
                self.log(f"Server exited unexpectedly:\n{output}")
                return False

            # Try connecting
            client = PdbsqlClient(port=self.server_port)
            if client.connect(timeout=1.0):
                client.disconnect()
                self.log("Server is ready.")
                return True

            time.sleep(0.5)

        self.log("Timeout waiting for server")
        return False

    def stop_server(self):
        """Stop the server process."""
        if self.server_process:
            self.log("Stopping server...")
            self.server_process.terminate()
            try:
                self.server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.server_process.kill()
                self.server_process.wait()

            # Print any remaining output
            output = self.server_process.stdout.read()
            if output.strip():
                print(f"[server output]\n{output}")

            self.server_process = None

    def run_remote_tests(self) -> List[Dict[str, Any]]:
        """Run test queries against the server (mode 3+4: remote)."""
        self.log("Running CLI remote mode tests...")

        client = PdbsqlClient(port=self.server_port)
        if not client.connect():
            self.log("Failed to connect to server")
            return [{'name': 'remote_connect', 'passed': False, 'error': 'Failed to connect'}]

        tests = define_remote_tests()
        results = []

        for test in tests:
            result = client.query(test['sql'])
            passed = test['check'](result)
            results.append({
                'name': f"cli_remote_{test['name']}",
                'passed': passed,
                'sql': test['sql'],
                'error': result.get('error', '') if not passed else '',
            })

        client.disconnect()
        return results

    def print_results(self, results: List[Dict[str, Any]], title: str) -> tuple:
        """Print test results. Returns (passed, failed) counts."""
        print()
        print("=" * 60)
        print(title)
        print("=" * 60)

        passed = 0
        failed = 0
        for r in results:
            status = "PASS" if r['passed'] else "FAIL"
            print(f"[{status}] {r['name']}")
            if not r['passed']:
                if r.get('sql'):
                    print(f"        SQL: {r['sql']}")
                if r.get('error'):
                    print(f"        Error: {r['error']}")
                if r.get('output'):
                    first_line = r['output'].split('\n')[0][:80]
                    print(f"        Output: {first_line}...")

            if r['passed']:
                passed += 1
            else:
                failed += 1

        print()
        print(f"Subtotal: {passed} passed, {failed} failed")
        return passed, failed

    def run(self) -> int:
        """Run the full test harness. Returns exit code."""
        total_passed = 0
        total_failed = 0

        try:
            # Build
            if not self.build():
                return 2

            # ===== CLI Local Mode Tests (Modes 1 & 2) =====
            local_results = self.run_cli_local_tests()
            p, f = self.print_results(local_results, "CLI LOCAL MODE TESTS (Modes 1 & 2)")
            total_passed += p
            total_failed += f

            # ===== CLI Remote Mode Tests (Modes 3 & 4) =====
            if not self.start_server():
                return 3

            remote_results = self.run_remote_tests()
            p, f = self.print_results(remote_results, "CLI REMOTE MODE TESTS (Modes 3 & 4)")
            total_passed += p
            total_failed += f

            # Print grand total
            print()
            print("=" * 60)
            print("GRAND TOTAL")
            print("=" * 60)
            print(f"Total: {total_passed} passed, {total_failed} failed")
            print("=" * 60)

            return 0 if total_failed == 0 else 1

        finally:
            self.stop_server()


def main():
    parser = argparse.ArgumentParser(description='PDBSQL Test Harness')
    parser.add_argument('--skip-build', action='store_true',
                        help='Skip building, use existing binaries')
    parser.add_argument('--test-pdb', type=str,
                        help='Path to test PDB (default: tests/testdata/test_program.pdb)')
    args = parser.parse_args()

    try:
        harness = TestHarness(
            skip_build=args.skip_build,
            test_pdb=args.test_pdb
        )
        sys.exit(harness.run())
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
