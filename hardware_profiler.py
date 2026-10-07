"""
hardware_profiler.py - Real-Time Hardware & Energy Profiler
============================================================
Adapted from energy_monitor.py in the security project.
Provides:
  - Real-time execution latency (milliseconds)
  - Peak memory footprint (RAM in MB) using tracemalloc + psutil
  - Process CPU utilization percentage
  - Dynamic TDP-based energy consumption (kWh) and CO2e emissions (kg)
  - Side-by-side Dual Profiling: Static Prediction vs. Dynamic Measured Impact
"""

import os
import sys
import time
import tracemalloc
from typing import Dict, Optional, Callable, Tuple, Any

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


CARBON_INTENSITY_KG_PER_KWH = 0.475
DEFAULT_TDP_WATTS = 45.0


class HardwareProfiler:
    """
    Measures runtime hardware performance and dynamic energy footprint of Python code.
    """

    def __init__(self, tdp_watts: float = DEFAULT_TDP_WATTS):
        self.tdp_watts = tdp_watts
        self.process = psutil.Process(os.getpid()) if PSUTIL_AVAILABLE else None

    def profile_execution(self, target_func: Callable, *args, **kwargs) -> Tuple[any, Dict]:
        """
        Executes target_func(*args, **kwargs) while recording real-time CPU, RAM, and latency.
        Returns (result, metrics_dict).
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

        hardware_metrics = {
            'status': 'ok' if exec_error is None else 'error',
            'error': exec_error,
            'latency_ms': round(elapsed_wall_s * 1000, 3),
            'cpu_time_ms': round(elapsed_cpu_s * 1000, 3),
            'cpu_percent': round(cpu_percent, 1),
            'peak_ram_mb': round(max(peak_traced_mb, rss_delta_mb), 4),
            'rss_memory_mb': round(final_rss_mb, 2),
            'dynamic_energy_kwh': round(dynamic_energy_kwh, 9),
            'dynamic_co2_kg': round(dynamic_co2_kg, 9),
            'device_tdp_watts': self.tdp_watts,
            'profiler_backend': 'psutil + tracemalloc' if PSUTIL_AVAILABLE else 'tracemalloc fallback',
            'summary': (
                f"{elapsed_wall_s * 1000:.2f} ms latency | "
                f"{peak_traced_mb:.3f} MB peak RAM | "
                f"{dynamic_energy_kwh:.8f} kWh dynamic energy"
            )
        }

        return result, hardware_metrics

    def profile_code_snippet(self, source_code: str, global_scope: Optional[dict] = None) -> Dict:
        """
        Compiles and executes a Python code snippet inside an isolated scope to measure hardware usage.
        """
        scope = global_scope or {}

        def _runner():
            compiled = compile(source_code, '<profiled_snippet>', 'exec')
            exec(compiled, scope)

        _, metrics = self.profile_execution(_runner)
        return metrics

    def _get_rss_mb(self) -> float:
        if self.process:
            try:
                return self.process.memory_info().rss / (1024 * 1024)
            except Exception:
                pass
        return 0.0


def measure_hardware(target_func: Callable, *args, **kwargs) -> Tuple[any, Dict]:
    """Helper to profile any function execution."""
    profiler = HardwareProfiler()
    return profiler.profile_execution(target_func, *args, **kwargs)


def profile_code(source_code: str) -> Dict:
    """Helper to profile arbitrary source code snippet."""
    profiler = HardwareProfiler()
    return profiler.profile_code_snippet(source_code)


if __name__ == "__main__":
    test_snippet = """
total = 0
for i in range(100_000):
    total += i * 2
data = [x ** 2 for x in range(10_000)]
"""
    print("Testing Hardware Profiler on loop snippet...")
    m = profile_code(test_snippet)
    print("Latency:", m['latency_ms'], "ms")
    print("CPU Time:", m['cpu_time_ms'], "ms")
    print("Peak RAM:", m['peak_ram_mb'], "MB")
    print("Dynamic Energy:", m['dynamic_energy_kwh'], "kWh")
    print("Backend:", m['profiler_backend'])
    print("Summary:", m['summary'])
