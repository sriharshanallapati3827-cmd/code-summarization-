"""
polyglot/cpp_profiler.py
━━━━━━━━━━━━━━━━━━━━━━━━
Dual-Mode Execution & Hardware Profiler for C++ source code.

Architecture:
  1. Gatekeeper Pre-Execution Inspection:
     - Scans C++ AST/tokens via CppSecurityAuditor for CRITICAL vulnerabilities
       (e.g. CWE-78 command injection: system(), popen(), exec*).
     - Blocks execution immediately if untrusted/malicious system operations are detected.
  2. Mode A: Compiled Subprocess Sandbox (Compiler Available):
     - Automatically detects g++ or clang++ on system PATH.
     - Wraps snippet with an entrypoint if main() is missing.
     - Compiles with safety and optimization flags (-O2 -Wall -std=c++17) in a temporary clean directory.
     - Executes compiled binary in an isolated subprocess with stripped environment variables.
     - Continuous psutil memory watchdog (PROFILER_MEMORY_LIMIT_MB) & timeout watchdog (PROFILER_TIMEOUT_SECONDS).
     - Process tree termination on limit violations.
  3. Mode B: Graceful Static Degradation (No Compiler Present or force_static=True):
     - Traverses Tree-sitter C++ AST to calculate max loop depth, loop counts, and recursion.
     - Derives theoretical Big-O algorithmic complexity (O(1), O(N), O(N^2), O(N^k), O(2^N)).
     - Estimates runtime latency, peak memory footprint, TDP energy (kWh), and CO2 emissions.
     - Ensures the pipeline never crashes in environments without a C++ compiler.
"""

from __future__ import annotations

import os
import re
import sys
import time
import shutil
import tempfile
import subprocess
from typing import Any, Dict, List, Optional, Tuple

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from polyglot.parser_factory import ParserFactory, SupportedLanguage
from polyglot.cpp_security_auditor import CppSecurityAuditor

CARBON_INTENSITY_KG_PER_KWH = 0.475
DEFAULT_TDP_WATTS = 45.0
DEFAULT_TIMEOUT_SECS = 2.0
DEFAULT_MEMORY_LIMIT_MB = 50.0

try:
    from agent_security.config import PROFILER_TIMEOUT_SECONDS, PROFILER_MEMORY_LIMIT_MB
    PROFILER_TIMEOUT_SECS = float(PROFILER_TIMEOUT_SECONDS)
    PROFILER_MEM_LIMIT_MB = float(PROFILER_MEMORY_LIMIT_MB)
except ImportError:
    PROFILER_TIMEOUT_SECS = DEFAULT_TIMEOUT_SECS
    PROFILER_MEM_LIMIT_MB = DEFAULT_MEMORY_LIMIT_MB


class CppProfiler:
    """
    Measures execution performance and energy consumption of C++ code
    with dual-mode support: compiled sandbox or static AST degradation.
    """

    def __init__(
        self,
        tdp_watts: float = DEFAULT_TDP_WATTS,
        timeout_seconds: float = PROFILER_TIMEOUT_SECS,
        memory_limit_mb: float = PROFILER_MEM_LIMIT_MB,
        compiler_path: Optional[str] = None,
    ) -> None:
        self.tdp_watts = tdp_watts
        self.timeout_seconds = timeout_seconds
        self.memory_limit_mb = memory_limit_mb
        self.compiler_path = compiler_path or self._discover_compiler()
        self.security_auditor = CppSecurityAuditor()

    @staticmethod
    def _discover_compiler() -> Optional[str]:
        """Check for g++ or clang++ on system PATH."""
        for candidate in ("g++", "clang++", "c++"):
            path = shutil.which(candidate)
            if path:
                return path
        return None

    def profile(self, source_code: str, force_static: bool = False) -> Dict[str, Any]:
        """
        Profiles the given C++ source code.
        If a compiler is available and force_static is False, compiles and runs in a sandbox.
        Otherwise, falls back gracefully to static AST complexity estimation.
        """
        if not source_code or not source_code.strip():
            return self._build_empty_metrics()

        # ── 1. Gatekeeper Pre-Execution Inspection ───────────────────────────
        audit_report = self.security_auditor.audit_code(source_code)
        findings = audit_report.get('findings', [])
        critical_violations = [
            f['message'] for f in findings
            if f.get('severity') == "CRITICAL" or f.get('cwe') == "CWE-78"
        ]

        if critical_violations:
            return {
                'blocked': True,
                'block_reasons': critical_violations,
                'timed_out': False,
                'memory_exceeded': False,
                'status': 'blocked',
                'error': 'C++ ExecBlocked: ' + '; '.join(critical_violations),
                'latency_ms': 0.0,
                'cpu_time_ms': 0.0,
                'cpu_percent': 0.0,
                'peak_ram_mb': 0.0,
                'rss_memory_mb': 0.0,
                'dynamic_energy_kwh': 0.0,
                'dynamic_co2_kg': 0.0,
                'device_tdp_watts': self.tdp_watts,
                'profiler_backend': 'blocked-by-cpp-gatekeeper',
                'execution_mode': 'gatekeeper_blocked',
                'summary': 'Execution blocked by C++ AST Gatekeeper (Critical CWE / Shell Injection)',
                'complexity': None,
                'max_loop_depth': None,
            }

        # ── 2. Route Execution vs Static Degradation ─────────────────────────
        if self.compiler_path and not force_static:
            return self._execute_compiled_sandbox(source_code)
        else:
            return self._estimate_static_complexity(source_code)

    def _execute_compiled_sandbox(self, source_code: str) -> Dict[str, Any]:
        """
        Compiles source code with g++/clang++ and executes inside an isolated subprocess sandbox.
        """
        assert self.compiler_path is not None
        compiler_name = os.path.basename(self.compiler_path)

        # Ensure main() entrypoint exists
        executable_code = self._ensure_main_entrypoint(source_code)

        temp_kwargs = {"ignore_cleanup_errors": True} if sys.version_info >= (3, 10) else {}
        with tempfile.TemporaryDirectory(**temp_kwargs) as temp_dir:
            src_file = os.path.join(temp_dir, "snippet.cpp")
            out_bin = os.path.join(temp_dir, "snippet.exe" if os.name == "nt" else "snippet.bin")

            with open(src_file, "w", encoding="utf-8") as f:
                f.write(executable_code)

            # Compile step: use -static to bundle runtime and avoid missing DLL / loader blocks
            compile_cmd = [
                self.compiler_path,
                "-O2",
                "-std=c++17",
                "-static",
                "-Wall",
                src_file,
                "-o",
                out_bin,
            ]

            try:
                comp_proc = subprocess.run(
                    compile_cmd,
                    cwd=temp_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10.0,
                )
            except subprocess.TimeoutExpired:
                return self._build_error_metrics(
                    "Compilation timed out after 10s",
                    status="compile_error",
                    backend=f"{compiler_name} compiler",
                )
            except Exception as exc:
                return self._build_error_metrics(
                    f"Compiler launch failed: {exc}",
                    status="compile_error",
                    backend=f"{compiler_name} compiler",
                )

            if comp_proc.returncode != 0:
                err_msg = comp_proc.stderr.strip() or comp_proc.stdout.strip()
                return self._build_error_metrics(
                    f"Compilation failed:\n{err_msg}",
                    status="compile_error",
                    backend=f"{compiler_name} compiler",
                )

            # Execution step inside isolated sandbox
            clean_env = {
                k: v for k, v in os.environ.items()
                if not any(t in k.upper() for t in ("KEY", "TOKEN", "SECRET", "AUTH", "PASS", "CREDENTIAL"))
            }

            start_wall = time.perf_counter()
            start_cpu = time.process_time()

            try:
                run_proc = subprocess.Popen(
                    [out_bin],
                    cwd=temp_dir,
                    env=clean_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=False,
                )
            except Exception as exc:
                return self._build_error_metrics(
                    f"Subprocess binary launch failed: {exc}",
                    status="error",
                    backend=f"{compiler_name} sandbox",
                )

            timed_out = False
            memory_exceeded = False
            rss_peak_mb = 0.0

            # Watchdog loop
            while run_proc.poll() is None:
                elapsed = time.perf_counter() - start_wall
                if elapsed > self.timeout_seconds:
                    timed_out = True
                    self._kill_process_tree(run_proc.pid)
                    break

                if PSUTIL_AVAILABLE:
                    try:
                        p = psutil.Process(run_proc.pid)
                        current_rss = p.memory_info().rss / (1024 * 1024)
                        for child in p.children(recursive=True):
                            current_rss += child.memory_info().rss / (1024 * 1024)
                        if current_rss > rss_peak_mb:
                            rss_peak_mb = current_rss
                        if current_rss > self.memory_limit_mb:
                            memory_exceeded = True
                            self._kill_process_tree(run_proc.pid)
                            break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                time.sleep(0.01)

            elapsed_wall_s = max(time.perf_counter() - start_wall, 0.000001)
            elapsed_cpu_s = max(time.process_time() - start_cpu, 0.000001)

            if timed_out or memory_exceeded:
                try:
                    run_proc.kill()
                    run_proc.communicate(timeout=0.2)
                except Exception:
                    pass

            if timed_out:
                return {
                    'blocked': False,
                    'block_reasons': [],
                    'timed_out': True,
                    'memory_exceeded': False,
                    'status': 'timeout',
                    'error': f'Execution exceeded {self.timeout_seconds}s watchdog limit (C++ Sandbox)',
                    'latency_ms': round(self.timeout_seconds * 1000, 3),
                    'cpu_time_ms': 0.0,
                    'cpu_percent': 0.0,
                    'peak_ram_mb': round(rss_peak_mb, 4),
                    'rss_memory_mb': round(rss_peak_mb, 2),
                    'dynamic_energy_kwh': 0.0,
                    'dynamic_co2_kg': 0.0,
                    'device_tdp_watts': self.tdp_watts,
                    'profiler_backend': f'{compiler_name} watchdog',
                    'execution_mode': 'compiled_sandbox',
                    'summary': f'Execution timed out after {self.timeout_seconds}s (C++ Sandbox)',
                    'complexity': None,
                    'max_loop_depth': None,
                }

            if memory_exceeded:
                return {
                    'blocked': False,
                    'block_reasons': [],
                    'timed_out': False,
                    'memory_exceeded': True,
                    'status': 'memory_exceeded',
                    'error': f'MemoryBomb: peak RAM {rss_peak_mb:.1f} MB exceeded {self.memory_limit_mb:.0f} MB ceiling (C++ Sandbox)',
                    'latency_ms': round(elapsed_wall_s * 1000, 3),
                    'cpu_time_ms': round(elapsed_cpu_s * 1000, 3),
                    'cpu_percent': 0.0,
                    'peak_ram_mb': round(rss_peak_mb, 4),
                    'rss_memory_mb': round(rss_peak_mb, 2),
                    'dynamic_energy_kwh': 0.0,
                    'dynamic_co2_kg': 0.0,
                    'device_tdp_watts': self.tdp_watts,
                    'profiler_backend': f'{compiler_name} watchdog',
                    'execution_mode': 'compiled_sandbox',
                    'summary': f'Memory ceiling exceeded: {rss_peak_mb:.1f} MB',
                    'complexity': None,
                    'max_loop_depth': None,
                }

            _, run_stderr = run_proc.communicate()
            if run_proc.returncode != 0:
                return {
                    'blocked': False,
                    'block_reasons': [],
                    'timed_out': False,
                    'memory_exceeded': False,
                    'status': 'error',
                    'error': f'Runtime exit code {run_proc.returncode}: {run_stderr.strip()[:100]}',
                    'latency_ms': round(elapsed_wall_s * 1000, 3),
                    'cpu_time_ms': round(elapsed_cpu_s * 1000, 3),
                    'cpu_percent': 0.0,
                    'peak_ram_mb': round(rss_peak_mb, 4),
                    'rss_memory_mb': round(rss_peak_mb, 2),
                    'dynamic_energy_kwh': 0.0,
                    'dynamic_co2_kg': 0.0,
                    'device_tdp_watts': self.tdp_watts,
                    'profiler_backend': f'{compiler_name} sandbox',
                    'execution_mode': 'compiled_sandbox',
                    'summary': f'Runtime error: exit code {run_proc.returncode}',
                    'complexity': None,
                    'max_loop_depth': None,
                }

            dynamic_energy_kwh = (elapsed_cpu_s * self.tdp_watts) / 3_600_000
            dynamic_co2_kg = dynamic_energy_kwh * CARBON_INTENSITY_KG_PER_KWH

            # Extract AST loop depth context for metadata companion
            complexity_info = self._analyze_ast_structure(source_code)

            return {
                'blocked': False,
                'block_reasons': [],
                'timed_out': False,
                'memory_exceeded': False,
                'status': 'ok',
                'error': None,
                'latency_ms': round(elapsed_wall_s * 1000, 3),
                'cpu_time_ms': round(elapsed_cpu_s * 1000, 3),
                'cpu_percent': 0.0,
                'peak_ram_mb': round(rss_peak_mb, 4),
                'rss_memory_mb': round(rss_peak_mb, 2),
                'dynamic_energy_kwh': round(dynamic_energy_kwh, 9),
                'dynamic_co2_kg': round(dynamic_co2_kg, 9),
                'device_tdp_watts': self.tdp_watts,
                'profiler_backend': f'{compiler_name} isolated-sandbox',
                'execution_mode': 'compiled_sandbox',
                'summary': (
                    f"{elapsed_wall_s * 1000:.2f} ms latency | "
                    f"{rss_peak_mb:.3f} MB peak RAM | "
                    f"{dynamic_energy_kwh:.8f} kWh dynamic energy"
                ),
                'complexity': complexity_info['complexity'],
                'max_loop_depth': complexity_info['max_loop_depth'],
            }

    def _estimate_static_complexity(self, source_code: str) -> Dict[str, Any]:
        """
        Graceful Static Degradation:
        Derives algorithmic complexity, loop depth, and synthetic eco-metrics
        directly from the C++ Tree-sitter AST without requiring any compiler.
        """
        structure = self._analyze_ast_structure(source_code)
        complexity = structure['complexity']
        max_depth = structure['max_loop_depth']

        # Synthetic latency baseline estimates per complexity class
        baseline_latencies = {
            "O(1)": 0.05,
            "O(N)": 1.15,
            "O(N^2)": 38.0,
            "O(N^k)": 140.0,
            "O(2^N)": 480.0,
        }
        estimated_latency_ms = baseline_latencies.get(complexity, 2.0)
        # Factor in code length scaling slightly
        lines_count = max(1, len(source_code.strip().splitlines()))
        estimated_latency_ms = round(estimated_latency_ms + (lines_count * 0.002), 3)

        estimated_cpu_s = max(0.000001, (estimated_latency_ms / 1000.0) * 0.85)
        estimated_peak_ram_mb = 4.2 + (max_depth * 0.8)

        dynamic_energy_kwh = (estimated_cpu_s * self.tdp_watts) / 3_600_000
        dynamic_co2_kg = dynamic_energy_kwh * CARBON_INTENSITY_KG_PER_KWH

        return {
            'blocked': False,
            'block_reasons': [],
            'timed_out': False,
            'memory_exceeded': False,
            'status': 'ok',
            'error': None,
            'latency_ms': round(estimated_latency_ms, 3),
            'cpu_time_ms': round(estimated_cpu_s * 1000, 3),
            'cpu_percent': 0.0,
            'peak_ram_mb': round(estimated_peak_ram_mb, 2),
            'rss_memory_mb': round(estimated_peak_ram_mb, 2),
            'dynamic_energy_kwh': round(dynamic_energy_kwh, 9),
            'dynamic_co2_kg': round(dynamic_co2_kg, 9),
            'device_tdp_watts': self.tdp_watts,
            'profiler_backend': 'static-pdg-degradation (no compiler)',
            'execution_mode': 'static_degradation',
            'complexity': complexity,
            'max_loop_depth': max_depth,
            'summary': (
                f"Static Estimation ({complexity}): {estimated_latency_ms:.2f} ms latency | "
                f"{estimated_peak_ram_mb:.1f} MB RAM | Eco Big-O: {complexity}"
            ),
        }

    def _analyze_ast_structure(self, source_code: str) -> Dict[str, Any]:
        """
        Parses C++ AST to calculate max loop nesting, loop counts, and detect recursion.
        """
        parsed = ParserFactory.parse(source_code, language=SupportedLanguage.CPP)
        root = parsed.root_node

        max_depth = 0
        total_loops = 0
        has_recursion = False

        loop_types = {"for_statement", "while_statement", "do_statement", "for_range_loop"}

        # Collect function names to check recursion
        func_names = set()
        stack = [root]
        while stack:
            curr = stack.pop()
            if curr.type == "function_declarator":
                # find identifier
                for child in curr.children:
                    if child.type == "identifier":
                        func_names.add(child.text.decode("utf-8", errors="ignore"))
            for child in curr.children:
                stack.append(child)

        def walk_loops(node, current_depth: int, current_func: Optional[str] = None):
            nonlocal max_depth, total_loops, has_recursion

            next_func = current_func
            if node.type == "function_definition":
                for child in node.children:
                    if child.type == "function_declarator":
                        for sub in child.children:
                            if sub.type == "identifier":
                                next_func = sub.text.decode("utf-8", errors="ignore")

            # Check recursive call
            if node.type == "call_expression" and next_func:
                for child in node.children:
                    if child.type == "identifier":
                        callee = child.text.decode("utf-8", errors="ignore")
                        if callee == next_func:
                            has_recursion = True

            is_loop = node.type in loop_types
            new_depth = current_depth + 1 if is_loop else current_depth
            if is_loop:
                total_loops += 1
                if new_depth > max_depth:
                    max_depth = new_depth

            for child in node.children:
                walk_loops(child, new_depth, next_func)

        walk_loops(root, 0, None)

        if has_recursion:
            complexity = "O(2^N)"
        elif max_depth == 0:
            complexity = "O(1)"
        elif max_depth == 1:
            complexity = "O(N)"
        elif max_depth == 2:
            complexity = "O(N^2)"
        else:
            complexity = "O(N^k)"

        return {
            'complexity': complexity,
            'max_loop_depth': max_depth,
            'total_loops': total_loops,
            'has_recursion': has_recursion,
        }

    def _ensure_main_entrypoint(self, code: str) -> str:
        """
        Wraps C++ snippet with a valid main() function if not already present.
        """
        if re.search(r'\bint\s+main\s*\(', code) or re.search(r'\bvoid\s+main\s*\(', code):
            return code

        # Append minimal execution harness
        return (
            code
            + "\n\n"
            + "int main() {\n"
            + "    return 0;\n"
            + "}\n"
        )

    def _kill_process_tree(self, pid: int) -> None:
        """Kill a subprocess and all of its descendant children."""
        if PSUTIL_AVAILABLE:
            try:
                parent = psutil.Process(pid)
                for child in parent.children(recursive=True):
                    try:
                        child.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                parent.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        else:
            try:
                os.kill(pid, 9)
            except Exception:
                pass

    def _build_empty_metrics(self) -> Dict[str, Any]:
        return {
            'blocked': False,
            'block_reasons': [],
            'timed_out': False,
            'memory_exceeded': False,
            'status': 'empty',
            'error': None,
            'latency_ms': 0.0,
            'cpu_time_ms': 0.0,
            'cpu_percent': 0.0,
            'peak_ram_mb': 0.0,
            'rss_memory_mb': 0.0,
            'dynamic_energy_kwh': 0.0,
            'dynamic_co2_kg': 0.0,
            'device_tdp_watts': self.tdp_watts,
            'profiler_backend': 'none',
            'execution_mode': 'none',
            'summary': 'Empty C++ source code provided',
            'complexity': None,
            'max_loop_depth': None,
        }

    def _build_error_metrics(self, error_msg: str, status: str, backend: str) -> Dict[str, Any]:
        return {
            'blocked': False,
            'block_reasons': [],
            'timed_out': False,
            'memory_exceeded': False,
            'status': status,
            'error': error_msg,
            'latency_ms': 0.0,
            'cpu_time_ms': 0.0,
            'cpu_percent': 0.0,
            'peak_ram_mb': 0.0,
            'rss_memory_mb': 0.0,
            'dynamic_energy_kwh': 0.0,
            'dynamic_co2_kg': 0.0,
            'device_tdp_watts': self.tdp_watts,
            'profiler_backend': backend,
            'execution_mode': 'compiled_sandbox',
            'summary': error_msg[:120],
            'complexity': None,
            'max_loop_depth': None,
        }


def profile_cpp_code(source_code: str, force_static: bool = False) -> Dict[str, Any]:
    """Helper function to profile C++ source code."""
    profiler = CppProfiler()
    return profiler.profile(source_code, force_static=force_static)
