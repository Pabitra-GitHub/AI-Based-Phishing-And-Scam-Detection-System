"""PhishGuard AI - Process Shutdown Helper
Finds processes listening on ports 8000 and 5173 and terminates them cleanly.
"""
import subprocess
import sys


def stop_servers():
    pids = set()
    try:
        output = subprocess.check_output(["netstat", "-aon"], text=True)
        for line in output.splitlines():
            line_str = line.strip()
            if "LISTENING" in line_str and (":8000" in line_str or ":5173" in line_str):
                parts = line_str.split()
                if parts:
                    pid = parts[-1]
                    if pid.isdigit() and int(pid) > 0:
                        pids.add(pid)
    except Exception as exc:
        print(f"Error checking ports: {exc}")

    for pid in sorted(pids):
        print(f"Stopping process PID {pid}...")
        try:
            subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True)
        except Exception as exc:
            print(f"Error terminating PID {pid}: {exc}")

    print("PhishGuard AI servers stopped.")


if __name__ == "__main__":
    stop_servers()
