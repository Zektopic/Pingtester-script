import subprocess
from tqdm import tqdm  # Install with `pip install tqdm`

def is_reachable(ip, timeout=1):
    """Checks if a device at the given IP address is reachable with a ping.

    Args:
        ip (str): The IP address to ping.
        timeout (int, optional): The timeout in seconds for the ping. Defaults to 1.

    Returns:
        bool: True if the ping is successful, False otherwise.
    """

    command = ["ping", "-c", "1", "-W", str(timeout), ip]  # -W for timeout in seconds (Linux)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()

    return b"bytes from" in output

if __name__ == "__main__":
    # Example usage: Check reachability within a specific subnet (replace with your allowed range)
    start_ip = "192.168.43.1"  # Adjust starting IP
    end_ip = "192.168.43.254"  # Adjust ending IP (modify for your network)

    # Ensure you have permission to scan this subnet!

    total_ips = int(end_ip.split(".")[-1]) - int(start_ip.split(".")[-1]) + 1
    with tqdm(total=total_ips, desc="Scanning network...") as pbar:  # Progress bar
        for i in range(1, total_ips + 1):
            ip_address = f"{start_ip.split('.')[0]}.{start_ip.split('.')[1]}.{start_ip.split('.')[2]}.{i}"
            pbar.set_description(f"Pinging {ip_address}...")  # Update progress indicator

            if is_reachable(ip_address):
                print(f"Device reachable at: {ip_address}")
            pbar.update(1)  # Update progress bar

    print("Scanning complete.")


