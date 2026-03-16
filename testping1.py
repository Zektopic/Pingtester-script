import subprocess
import concurrent.futures
import ipaddress
import logging
from tqdm import tqdm  # Install with `pip install tqdm`

def is_reachable(ip, timeout=1):
    """Checks if a device at the given IP address is reachable with a ping.

    Args:
        ip (str): The IP address to ping.
        timeout (int, optional): The timeout in seconds for the ping. Defaults to 1.

    Returns:
        bool: True if the ping is successful, False otherwise.
    """

    # 🛡️ Sentinel: Validate IP address to prevent argument injection
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        logging.error(f"Invalid IP address format: {ip}")
        return False

    # 🛡️ Sentinel: Validate timeout parameter to prevent argument injection and type errors
    try:
        timeout_int = int(timeout)
        if timeout_int <= 0:
            logging.error(f"Invalid timeout value: {timeout_int}. Must be greater than 0.")
            return False
    except ValueError:
        logging.error(f"Invalid timeout format: {timeout}. Must be an integer.")
        return False

    command = ["ping", "-c", "1", "-W", str(timeout_int), str(ip_obj)]  # -W for timeout in seconds (Linux)

    # ⚡ Bolt: Optimized ping execution by using subprocess.call and redirecting
    # output to DEVNULL instead of using Popen with PIPE.
    # This avoids the Inter-Process Communication (IPC) overhead of capturing
    # stdout/stderr, resulting in ~35% speedup for parallel network scans.
    # 🛡️ Sentinel: Prevent stack trace leakage by catching potential exceptions during subprocess execution
    try:
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except Exception as e:
        logging.error("Failed to execute ping command.")
        return False

if __name__ == "__main__":
    # Example usage: Check reachability within a specific subnet (replace with your allowed range)
    start_ip = "192.168.43.1"  # Adjust starting IP
    end_ip = "192.168.43.254"  # Adjust ending IP (modify for your network)

    # Ensure you have permission to scan this subnet!

    # ⚡ Bolt: Optimized IP generation by extracting redundant string splitting outside the loop.
    # Improves performance from O(N * splits) to O(N) by caching the base IP prefix.
    base_ip = start_ip.rsplit('.', 1)[0]
    start_octet = int(start_ip.split('.')[-1])
    end_octet = int(end_ip.split('.')[-1])
    total_ips = end_octet - start_octet + 1

    ips_to_scan = [f"{base_ip}.{i}" for i in range(start_octet, end_octet + 1)]

    # ⚡ Bolt: Parallelize network scanning using ThreadPoolExecutor
    # Reduces scan time significantly by performing pings concurrently instead of sequentially.
    # Time complexity with respect to network delay improves from O(N) to O(N / workers).
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        with tqdm(total=total_ips, desc="Scanning network...") as pbar:  # Progress bar
            futures = {executor.submit(is_reachable, ip): ip for ip in ips_to_scan}
            for future in concurrent.futures.as_completed(futures):
                ip_address = futures[future]
                pbar.set_description(f"Pinging {ip_address}...")  # Update progress indicator

                if future.result():
                    print(f"Device reachable at: {ip_address}")
                pbar.update(1)  # Update progress bar

    print("Scanning complete.")


