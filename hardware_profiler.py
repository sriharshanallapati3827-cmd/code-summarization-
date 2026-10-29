"""
hardware_profiler.py - Real-Time Hardware & Energy Profiler
============================================================
Adapted from energy_monitor.py in the security project.
Provides:
  - Real-time execution latency (milliseconds)
  - Peak memory footprint (RAM in MB) using tracemalloc + psutil
  - Process CPU utilization percentage
  - Dynamic TDP-based energy consumption (kWh) and CO2e emissions (kg)
  - Isolated subprocess sandbox execution (0 in-process exec on user code)
  - AST gatekeeper static analysis before execution
"""

import os
import sys
import time
import json
import tempfile
import subprocess
import tracemalloc
from typing import Dict, Optional, Callable, Tuple, Any

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# ── Pillar 3: AST Gatekeeper + limits ─────────────────────────────────────────
try:
    from agent_security.ast_gatekeeper import scan, GatekeeperReport
    from agent_security.config import PROFILER_TIMEOUT_SECONDS, PROFILER_MEMORY_LIMIT_MB
    _GUARD_AVAILABLE = True
except ImportError:
    _GUARD_AVAILABLE = False
    PROFILER_TIMEOUT_SECONDS = 2.0
    PROFILER_MEMORY_LIMIT_MB = 50


CARBON_INTENSITY_KG_PER_KWH = 0.475
DEFAULT_TDP_WATTS = 45.0


class HardwareProfiler:
    """
    Measures runtime hardware performance and dynamic energy footprint of Python code.
    Runs untrusted user code snippets strictly inside an isolated subprocess sandbox.
    """

    def __init__(self, tdp_watts: float = DEFAULT_TDP_WATTS):
        self.tdp_watts = tdp_watts
        self.process = psutil.Process(os.getpid()) if PSUTIL_AVAILABLE else None

    def profile_execution(self, target_func: Callable, *args, **kwargs) -> Tuple[Any, Dict]:
        """
        Executes target_func(*args, **kwargs) while recording real-time CPU, RAM, and latency.
        Returns (result, metrics_dict).
        Guarantees all 4 security keys (blocked, block_reasons, timed_out, memory_exceeded)
        are present.
        """
        tracemalloc.start()
        start_wall = time.perf_counter()
        start_cpu = time.process_time()

        initial_rss_mb = self._get_rss_mb()
        if self.process:
            self.process.cpu_percent(interval=None)

        result = None
        exec_error = None
        try:
            result = target_func(*args, **kwargs)
        except Exception as e:
            exec_error = str(e)

        elapsed_wall_s = max(time.perf_counter() - start_wall, 0.000001)
        elapsed_cpu_s = max(time.process_time() - start_cpu, 0.000001)

        current_mem, peak_traced_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        final_rss_mb = self._get_rss_mb()
        peak_traced_mb = peak_traced_mem / (1024 * 1024)
        rss_delta_mb = max(0.0, final_rss_mb - initial_rss_mb)

        cpu_percent = self.process.cpu_percent(interval=None) if self.process else 0.0

        # Dynamic Energy Calculation: (CPU Time * Device TDP) / (3,600,000 W*s per kWh)
        dynamic_energy_kwh = (elapsed_cpu_s * self.tdp_watts) / 3_600_000
        dynamic_co2_kg = dynamic_energy_kwh * CARBON_INTENSITY_KG_PER_KWH

        memory_limit_mb = float(PROFILER_MEMORY_LIMIT_MB)
        peak_ram_mb = round(max(peak_traced_mb, rss_delta_mb), 4)
        is_mem_exceeded = peak_ram_mb > memory_limit_mb

        hardware_metrics = {
            'blocked': False,
            'block_reasons': [],
            'timed_out': False,
            'memory_exceeded': is_mem_exceeded,
            'status': 'memory_exceeded' if is_mem_exceeded else ('ok' if exec_error is None else 'error'),
            'error': f'MemoryBomb: peak RAM {peak_ram_mb:.1f} MB exceeded {memory_limit_mb:.0f} MB ceiling' if is_mem_exceeded else exec_error,
            'latency_ms': round(elapsed_wall_s * 1000, 3),
            'cpu_time_ms': round(elapsed_cpu_s * 1000, 3),
            'cpu_percent': round(cpu_percent, 1),
            'peak_ram_mb': peak_ram_mb,
            'rss_memory_mb': round(final_rss_mb, 2),
            'dynamic_energy_kwh': round(dynamic_energy_kwh, 9),
            'dynamic_co2_kg': round(dynamic_co2_kg, 9),
            'device_tdp_watts': self.tdp_watts,
            'profiler_backend': 'psutil + tracemalloc' if PSUTIL_AVAILABLE else 'tracemalloc fallback',
            'summary': (
                f"{elapsed_wall_s * 1000:.2f} ms latency | "
                f"{peak_traced_mb:.3f} MB peak RAM | "
                f"{dynamic_energy_kwh:.8f} kWh dynamic energy"
            ),
        }

        return result, hardware_metrics

    def profile_code_snippet(self, source_code: str, global_scope: Optional[dict] = None) -> Dict:
        """
        Executes a Python code snippet inside an isolated subprocess sandbox.
        NEVER calls exec() on user code in the host process.

        Pillar-3 hardening:
          1. AST Gatekeeper: iterative traversal blocks forbidden modules/calls/dunders.
          2. Isolated Subprocess: executes with `python -I` in a temporary clean directory.
          3. Environment sanitization: all sensitive API keys/tokens stripped.
          4. Process-tree kill on timeout (PROFILER_TIMEOUT_SECONDS).
          5. Memory limit monitoring (PROFILER_MEMORY_LIMIT_MB).
        """
        # ── 1. AST Gatekeeper Pre-Execution Inspection ───────────────────────
        if _GUARD_AVAILABLE:
            report = scan(source_code)
            if not report.is_safe:
                return {
                    'blocked': True,
                    'block_reasons': report.block_reasons,
                    'timed_out': False,
                    'memory_exceeded': False,
                    'status': 'blocked',
                    'error': 'ExecBlocked: ' + '; '.join(report.block_reasons),
                    'latency_ms': 0.0,
                    'cpu_time_ms': 0.0,
                    'cpu_percent': 0.0,
                    'peak_ram_mb': 0.0,
                    'rss_memory_mb': 0.0,
                    'dynamic_energy_kwh': 0.0,
                    'dynamic_co2_kg': 0.0,
                    'device_tdp_watts': self.tdp_watts,
                    'profiler_backend': 'blocked-by-ast-gatekeeper',
                    'summary': 'Execution blocked by AST Gatekeeper (Pillar 3)',
                }

        timeout_secs = float(PROFILER_TIMEOUT_SECONDS)
        memory_limit_mb = float(PROFILER_MEMORY_LIMIT_MB)

        # ── 2. Isolated Subprocess Sandbox Execution ─────────────────────────
        # Create temporary working directory that is strictly cleaned up
        temp_kwargs = {"ignore_cleanup_errors": True} if sys.version_info >= (3, 10) else {}
        with tempfile.TemporaryDirectory(**temp_kwargs) as temp_dir:
            snippet_path = os.path.join(temp_dir, "snippet.py")
            with open(snippet_path, "w", encoding="utf-8") as f:
                f.write(source_code)

            # Harness script executed inside the sandbox subprocess
            harness_path = os.path.join(temp_dir, "harness.py")
            harness_code = """
import sys
import time
import json
import tracemalloc

tracemalloc.start()
start_wall = time.perf_counter()
start_cpu = time.process_time()
exec_error = None

try:
    with open("snippet.py", "rb") as f:
        compiled = compile(f.read(), "snippet.py", "exec")
    scope = {}
    exec(compiled, scope)
except Exception as e:
    exec_error = str(e)

elapsed_wall_s = max(time.perf_counter() - start_wall, 0.000001)
elapsed_cpu_s = max(time.process_time() - start_cpu, 0.000001)

current_mem, peak_traced_mem = tracemalloc.get_traced_memory()
tracemalloc.stop()
peak_traced_mb = peak_traced_mem / (1024 * 1024)

result_data = {
    "status": "ok" if exec_error is None else "error",
    "error": exec_error,
    "elapsed_wall_s": elapsed_wall_s,
    "elapsed_cpu_s": elapsed_cpu_s,
    "peak_traced_mb": peak_traced_mb
}

print("__METRICS_JSON__" + json.dumps(result_data))
"""
            with open(harness_path, "w", encoding="utf-8") as f:
                f.write(harness_code)

            # Sanitize environment: strip any secrets, keys, or credentials
            clean_env = {
                k: v for k, v in os.environ.items()
                if not any(token in k.upper() for token in ("KEY", "TOKEN", "SECRET", "AUTH", "PASS", "CREDENTIAL"))
            }

            try:
                proc = subprocess.Popen(
                    [sys.executable, "-I", "harness.py"],
                    cwd=temp_dir,
                    env=clean_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=False,
                )
            except Exception as exc:
                return {
                    'blocked': False,
                    'block_reasons': [],
                    'timed_out': False,
                    'memory_exceeded': False,
                    'status': 'error',
                    'error': f'Failed to launch sandboxed subprocess: {exc}',
                    'latency_ms': 0.0,
                    'cpu_time_ms': 0.0,
                    'cpu_percent': 0.0,
                    'peak_ram_mb': 0.0,
                    'rss_memory_mb': 0.0,
                    'dynamic_energy_kwh': 0.0,
                    'dynamic_co2_kg': 0.0,
                    'device_tdp_watts': self.tdp_watts,
                    'profiler_backend': 'subprocess-sandbox',
                    'summary': f'Subprocess launch failed: {exc}',
                }

            start_t = time.perf_counter()
            timed_out = False
            memory_exceeded = False
            rss_peak_mb = 0.0

            # ── 3. Watchdog Monitoring Loop (Timeout + RAM Watchdog) ──────────
            while proc.poll() is None:
                elapsed = time.perf_counter() - start_t
                if elapsed > timeout_secs:
                    timed_out = True
                    self._kill_process_tree(proc.pid)
                    break

                # Continuous psutil memory check
                if PSUTIL_AVAILABLE:
                    try:
                        p = psutil.Process(proc.pid)
                        current_rss = p.memory_info().rss / (1024 * 1024)
                        for child in p.children(recursive=True):
                            current_rss += child.memory_info().rss / (1024 * 1024)
                        if current_rss > rss_peak_mb:
                            rss_peak_mb = current_rss
                        if current_rss > memory_limit_mb:
                            memory_exceeded = True
                            self._kill_process_tree(proc.pid)
                            break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                time.sleep(0.02)

            if timed_out:
                return {
                    'blocked': False,
                    'block_reasons': [],
                    'timed_out': True,
                    'memory_exceeded': False,
                    'status': 'timeout',
                    'error': f'Execution exceeded {timeout_secs}s watchdog limit (Pillar 3)',
                    'latency_ms': round(timeout_secs * 1000, 3),
                    'cpu_time_ms': 0.0,
                    'cpu_percent': 0.0,
                    'peak_ram_mb': 0.0,
                    'rss_memory_mb': 0.0,
                    'dynamic_energy_kwh': 0.0,
                    'dynamic_co2_kg': 0.0,
                    'device_tdp_watts': self.tdp_watts,
                    'profiler_backend': 'blocked-by-timeout-watchdog',
                    'summary': f'Execution timed out after {timeout_secs}s (Pillar 3)',
                }

            if memory_exceeded:
                return {
                    'blocked': False,
                    'block_reasons': [],
                    'timed_out': False,
                    'memory_exceeded': True,
                    'status': 'memory_exceeded',
                    'error': f'MemoryBomb: peak RAM {rss_peak_mb:.1f} MB exceeded {memory_limit_mb:.0f} MB ceiling (Pillar 3)',
                    'latency_ms': round((time.perf_counter() - start_t) * 1000, 3),
                    'cpu_time_ms': 0.0,
                    'cpu_percent': 0.0,
                    'peak_ram_mb': round(rss_peak_mb, 4),
                    'rss_memory_mb': round(rss_peak_mb, 2),
                    'dynamic_energy_kwh': 0.0,
                    'dynamic_co2_kg': 0.0,
                    'device_tdp_watts': self.tdp_watts,
                    'profiler_backend': 'blocked-by-memory-watchdog',
                    'summary': f'Memory limit exceeded: {rss_peak_mb:.1f} MB (Pillar 3)',
                }

            # ── 4. Collect Subprocess Output & Metrics ────────────────────────
            stdout, stderr = proc.communicate()
            metrics_payload = None

            for line in stdout.splitlines():
                if line.startswith("__METRICS_JSON__"):
                    try:
                        metrics_payload = json.loads(line[len("__METRICS_JSON__"):])
                        break
                    except Exception:
                        pass

            if not metrics_payload:
                return {
                    'blocked': False,
                    'block_reasons': [],
                    'timed_out': False,
                    'memory_exceeded': False,
                    'status': 'error',
                    'error': stderr.strip() or 'No metrics returned from sandbox subprocess',
                    'latency_ms': 0.0,
                    'cpu_time_ms': 0.0,
                    'cpu_percent': 0.0,
                    'peak_ram_mb': 0.0,
                    'rss_memory_mb': 0.0,
                    'dynamic_energy_kwh': 0.0,
                    'dynamic_co2_kg': 0.0,
                    'device_tdp_watts': self.tdp_watts,
                    'profiler_backend': 'subprocess-sandbox',
                    'summary': f'Subprocess execution failed: {stderr.strip()[:100]}',
                }

            wall_s = metrics_payload.get("elapsed_wall_s", 0.0)
            cpu_s = metrics_payload.get("elapsed_cpu_s", 0.0)
            traced_mb = metrics_payload.get("peak_traced_mb", 0.0)
            peak_mb = max(traced_mb, rss_peak_mb)
            sub_status = metrics_payload.get("status", "ok")
            sub_err = metrics_payload.get("error")

            # Post-execution peak memory check
            if peak_mb > memory_limit_mb:
                return {
                    'blocked': False,
                    'block_reasons': [],
                    'timed_out': False,
                    'memory_exceeded': True,
                    'status': 'memory_exceeded',
                    'error': f'MemoryBomb: peak RAM {peak_mb:.1f} MB exceeded {memory_limit_mb:.0f} MB ceiling (Pillar 3)',
                    'latency_ms': round(wall_s * 1000, 3),
                    'cpu_time_ms': round(cpu_s * 1000, 3),
                    'cpu_percent': 0.0,
                    'peak_ram_mb': round(peak_mb, 4),
                    'rss_memory_mb': round(peak_mb, 2),
                    'dynamic_energy_kwh': 0.0,
                    'dynamic_co2_kg': 0.0,
                    'device_tdp_watts': self.tdp_watts,
                    'profiler_backend': 'subprocess-sandbox',
                    'summary': f'Memory ceiling exceeded: {peak_mb:.1f} MB',
                }

            dynamic_energy_kwh = (cpu_s * self.tdp_watts) / 3_600_000
            dynamic_co2_kg = dynamic_energy_kwh * CARBON_INTENSITY_KG_PER_KWH

            return {
                'blocked': False,
                'block_reasons': [],
                'timed_out': False,
                'memory_exceeded': False,
                'status': sub_status,
                'error': sub_err,
                'latency_ms': round(wall_s * 1000, 3),
                'cpu_time_ms': round(cpu_s * 1000, 3),
                'cpu_percent': 0.0,
                'peak_ram_mb': round(peak_mb, 4),
                'rss_memory_mb': round(peak_mb, 2),
                'dynamic_energy_kwh': round(dynamic_energy_kwh, 9),
                'dynamic_co2_kg': round(dynamic_co2_kg, 9),
                'device_tdp_watts': self.tdp_watts,
                'profiler_backend': 'subprocess-sandbox',
                'summary': (
                    f"{wall_s * 1000:.2f} ms latency | "
                    f"{peak_mb:.3f} MB peak RAM | "
                    f"{dynamic_energy_kwh:.8f} kWh dynamic energy"
                ),
            }

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

    def _get_rss_mb(self) -> float:
        if self.process:
            try:
                return self.process.memory_info().rss / (1024 * 1024)
            except Exception:
                pass
        return 0.0


def measure_hardware(target_func: Callable, *args, **kwargs) -> Tuple[Any, Dict]:
    """Helper to profile any function execution."""
    profiler = HardwareProfiler()
    return profiler.profile_execution(target_func, *args, **kwargs)


def profile_code(source_code: str) -> Dict:
    """Helper to profile arbitrary source code snippet in sandbox."""
    profiler = HardwareProfiler()
    return profiler.profile_code_snippet(source_code)


if __name__ == "__main__":
    test_snippet = """
total = 0
for i in range(100_000):
    total += i * 2
data = [x ** 2 for x in range(10_000)]
"""
    print("Testing Sandboxed Subprocess Hardware Profiler...")
    m = profile_code(test_snippet)
    print("Blocked:", m['blocked'])
    print("Timed Out:", m['timed_out'])
    print("Memory Exceeded:", m['memory_exceeded'])
    print("Status:", m['status'])
    print("Latency:", m['latency_ms'], "ms")
    print("Peak RAM:", m['peak_ram_mb'], "MB")
    print("Backend:", m['profiler_backend'])
    print("Summary:", m['summary'])
