## 2024-05-14 - Subprocess Communication Overhead
**Learning:** In Python, using `subprocess.Popen(..., stdout=subprocess.PIPE, stderr=subprocess.PIPE)` and `process.communicate()` is significantly slower than using `subprocess.call(..., stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)` when you only care about the exit code. Capturing output creates significant Inter-Process Communication (IPC) overhead. Benchmarks showed parallel execution of the latter approach is ~35% faster.
**Action:** When invoking external commands where only success/failure matters, prefer `subprocess.call` with `DEVNULL` instead of capturing `PIPE` output to parse.

## 2026-03-16 - ipaddress vs socket
**Learning:** Using `ipaddress.ip_address` for IP validation and casting it back to string incurs significant performance overhead. It is about ~14x slower than using `socket.inet_pton`.
**Action:** When only checking if a string is a valid IP address and no advanced IP manipulation is needed, prefer `socket.inet_pton` for higher performance in network scanning utilities.
