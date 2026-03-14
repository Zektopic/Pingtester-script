## 2024-05-18 - Input Validation for System Commands
**Vulnerability:** Argument injection risk in `subprocess.Popen` via unsanitized IP parameter.
**Learning:** `subprocess.Popen` without `shell=True` mitigates shell injection but is still vulnerable to argument injection (e.g., `-h` or other flags).
**Prevention:** Strictly validate input formats using appropriate libraries (e.g., `ipaddress` for IP strings) before passing them to system commands.
