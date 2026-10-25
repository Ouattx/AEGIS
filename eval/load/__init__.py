"""Load-test harness for AEGIS scale-out (synthetic traffic, see ``run_load.py``).

Importing the package pins native libraries to one thread per process (unless the caller
already chose): parallelism comes from shard worker processes, and per-core CPU costs must
not include OpenMP threads spinning on the other cores. This runs before LightGBM loads.
"""
import os

for _var in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ.setdefault(_var, "1")
