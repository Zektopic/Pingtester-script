## 2024-05-14 - Subprocess Communication Overhead
**Learning:** In Python, using `subprocess.Popen(..., stdout=subprocess.PIPE, stderr=subprocess.PIPE)` and `process.communicate()` is significantly slower than using `subprocess.call(..., stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)` when you only care about the exit code. Capturing output creates significant Inter-Process Communication (IPC) overhead. Benchmarks showed parallel execution of the latter approach is ~35% faster.
**Action:** When invoking external commands where only success/failure matters, prefer `subprocess.call` with `DEVNULL` instead of capturing `PIPE` output to parse.

## 2024-05-18 - [Tqdm Progress Bar Overhead]
**Learning:** Calling `pbar.set_description()` on a `tqdm` progress bar inside a fast concurrent loop (like `concurrent.futures.as_completed`) introduces a significant synchronous console I/O bottleneck that drastically slows down execution.
**Action:** Avoid dynamic console output updates in rapid loops; instead, rely on the basic progress bar advancement (`pbar.update(1)`) or batch updates to prevent I/O blocking.

## 2024-05-24 - [Thread Pool Size for Concurrent I/O]
**Learning:** Hardcoded, small thread pool limits (like `max_workers=50`) act as severe bottlenecks for highly I/O bound concurrent network tasks like ping sweeping an entire subnet. Because pings spend most of their time waiting on network timeouts, artificially restricting concurrency forces the pool to process timeouts in batches, drastically increasing total scan time.
**Action:** When using `concurrent.futures.ThreadPoolExecutor` for pure I/O or network tasks where the operation is mostly waiting, dynamically size `max_workers` to handle the full workload concurrently (e.g., `min(total_tasks, 256)`) to complete all timeouts in parallel.

## 2026-03-23 - [Subprocess PATH lookup overhead]
**Learning:** Calling `subprocess.call(["ping", ...])` without the absolute path causes the OS/Python interpreter to repeatedly scan through all directories listed in the `PATH` environment variable to locate the executable file for *every single* invocation. In highly concurrent or iterative loops (like a network sweep using `ThreadPoolExecutor`), this redundant lookup creates a measurable performance bottleneck.
**Action:** When invoking external commands repetitively via `subprocess` in a tight loop or concurrently, cache the absolute path of the executable once at module initialization using `shutil.which("command") or "command"` to eliminate `PATH` traversal overhead.
