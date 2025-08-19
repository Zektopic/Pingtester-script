# Network Scanner

This script, `testping1.py`, is a simple network scanner that checks for reachable devices within a specified IP address range. It uses the `ping` command to determine if a device is online.

## Features

- Pings a range of IP addresses.
- Displays reachable IP addresses.
- Shows a progress bar during the scan.

## Requirements

- Python 3
- `tqdm` library

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. Install the required Python library:
   ```bash
   pip install -r requirements.txt
   ```
   *(Note: A `requirements.txt` file will be added to the project)*

## Usage

Run the script from your terminal:

```bash
python testping1.py
```

The script is pre-configured to scan the `192.168.43.1` to `192.168.43.254` IP range. You can modify the `start_ip` and `end_ip` variables in `testping1.py` to scan a different range.

**Important:** Ensure you have permission to scan the network before running this script. Unauthorized network scanning can be disruptive and may be against the terms of service for the network you are on.
