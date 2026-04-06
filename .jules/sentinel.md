## 2024-05-17 - Unvalidated Secondary Parameters
**Vulnerability:** The `timeout` parameter in `is_reachable` was not validated before being passed to `subprocess.call`. This allowed passing unexpected flags (like `-h` which caused the process to hang) or potentially argument injection if the string format changed.
**Learning:** Security validation often focuses heavily on the primary input (like an IP address). However, secondary or "optional" parameters passed to system commands are equally dangerous if unsanitized, even if they seem benign or are expected to be integers.
**Prevention:** Validate and type-cast *every* parameter that forms part of a shell command argument array, ensuring it strictly conforms to expected types (e.g., using `int()` and checking `> 0` for timeouts).
## 2024-05-20 - [Unhandled Exception ThreadPool Leak]
**Vulnerability:** Unhandled exceptions (e.g., `OSError` from missing `ping` binary) in `subprocess.call` within `ThreadPoolExecutor` workers bubbled up, crashing the aggregator process and leaking internal system details/stack traces. Additionally, a lack of timeout limits posed a Denial of Service (DoS) risk through resource exhaustion, tying up worker threads.
**Learning:** `ThreadPoolExecutor` does not inherently catch unhandled exceptions in its worker tasks; calling `.result()` or iterating over `as_completed()` will re-raise them. External subprocess calls are a high-risk vector for unpredictable `OSErrors`.
**Prevention:** Always wrap external system calls (`subprocess.call`, file operations, network requests) inside worker functions with secure `try...except` blocks. Log generic errors to avoid leaking stack traces, and implement upper bounds on input values that govern resource allocation (e.g., thread duration via timeout limits).
## 2024-05-23 - [Server-Side Request Forgery Prevention in Utils]
**Vulnerability:** The `is_reachable` utility function validated if an IP was correctly formatted, but did not restrict the semantic destination. This allowed Server-Side Request Forgery (SSRF) where the scanner could be manipulated into pinging loopback (`127.0.0.1`), link-local (e.g., AWS metadata `169.254.169.254`), or multicast addresses.
**Learning:** Input validation is not just about syntax (like `ipaddress.ip_address`), but also about semantics and intended use. Even a simple `ping` utility can become an SSRF vector if it allows querying internal or restricted network ranges.
**Prevention:** Always implement explicit allow-lists or block-lists for network destinations based on business logic. Use built-in library properties (like `ip_obj.is_loopback`, `ip_obj.is_link_local`) to robustly filter out non-routable or restricted administrative IP ranges before attempting network requests.
## 2024-05-24 - [Extended Server-Side Request Forgery Prevention in Utils]
**Vulnerability:** Even when blocking standard internal ranges (loopback, link-local, multicast, unspecified), other reserved IPs like the broadcast address (`255.255.255.255`) could still be targeted. Pinging broadcast addresses can lead to amplification attacks or unintended network noise.
**Learning:** Python's `ipaddress` module separates `is_multicast` from `is_reserved` (which includes broadcast addresses). A comprehensive SSRF defense must cover all non-standard routing destinations.
**Prevention:** Extend network block-lists to include `ip_obj.is_reserved` to catch broadcast addresses and other IETF-reserved network ranges that shouldn't be targeted in a standard scan.
## 2024-05-24 - Unhandled TypeError when comparing IP versions
**Vulnerability:** Comparing `ipaddress` objects of different versions (e.g., IPv4 and IPv6) raises a `TypeError`, which if unhandled, causes the application to crash abruptly (Denial of Service risk).
**Learning:** `ipaddress` module's comparison operators (`<`, `>`, `<=`, `>=`) are strictly typed by IP version. They do not implicitly convert or handle cross-version comparisons securely.
**Prevention:** Always validate that `ipaddress` objects share the same `.version` before comparing them, and catch `TypeError` alongside `ValueError` when parsing or manipulating generic IP address inputs.
## 2024-05-24 - Unsafe Relative Path Execution
**Vulnerability:** The application used `shutil.which("ping") or "ping"`. If `ping` was not found in the system `PATH`, it fell back to executing the relative string `"ping"`. This could allow arbitrary code execution or local privilege escalation if run from a directory containing a malicious executable named `ping`.
**Learning:** Never fallback to relative command names when a system binary is expected. If a required binary is missing from the system path, the application should fail securely rather than attempting a risky, unverified local execution.
**Prevention:** Remove fallback logic for critical system commands. Use `shutil.which()` and raise an exception (e.g., `RuntimeError`) if the expected binary is `None`.

## 2024-04-03 - Thread crash via OverflowError in float to int cast
**Vulnerability:** Application crashes and potential DoS due to `OverflowError` when untrusted input containing `Infinity` or `NaN` is parsed (e.g., from JSON) and subsequently converted to an integer using `int()`.
**Learning:** Python's `int()` function raises `OverflowError` instead of `ValueError` or `TypeError` when it encounters infinite float values. If not explicitly caught, this can crash worker thread pools processing untrusted user input.
**Prevention:** When converting untrusted input to integers using `int()`, explicitly catch `OverflowError` alongside `ValueError` and `TypeError` to ensure graceful handling.
## 2025-04-06 - IPv6 Scope ID Injection Vulnerability
**Vulnerability:** The Python `ipaddress` module preserves arbitrary characters (including newlines and control characters) within the `scope_id` of an `IPv6Address` (e.g., `fe80::1%eth0\n`).
**Learning:** If this object is cast to a string via `str(ip_obj)` and passed directly to subprocess commands or logs without sanitization, it introduces a risk of Log Injection and unpredictable Argument Injection, even with `shell=False`.
**Prevention:** Strictly validate `ip_obj.scope_id` using a regex like `re.fullmatch(r'[\w\-]+', ip_obj.scope_id)` before interacting with external systems or APIs.
