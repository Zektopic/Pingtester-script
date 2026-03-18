## 2024-05-14 - Subprocess Communication Overhead
**Learning:** In Python, using `subprocess.Popen(..., stdout=subprocess.PIPE, stderr=subprocess.PIPE)` and `process.communicate()` is significantly slower than using `subprocess.call(..., stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)` when you only care about the exit code. Capturing output creates significant Inter-Process Communication (IPC) overhead. Benchmarks showed parallel execution of the latter approach is ~35% faster.
**Action:** When invoking external commands where only success/failure matters, prefer `subprocess.call` with `DEVNULL` instead of capturing `PIPE` output to parse.

## 2024-05-18 - [Tqdm Progress Bar Overhead]
**Learning:** Calling `pbar.set_description()` on a `tqdm` progress bar inside a fast concurrent loop (like `concurrent.futures.as_completed`) introduces a significant synchronous console I/O bottleneck that drastically slows down execution.
**Action:** Avoid dynamic console output updates in rapid loops; instead, rely on the basic progress bar advancement (`pbar.update(1)`) or batch updates to prevent I/O blocking.
