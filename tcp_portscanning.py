import socket
import threading
import queue
import logging
from datetime import datetime

# ---------- CONFIG ----------
THREAD_COUNT = 50
TIMEOUT = 3
LOG_FILE = "scan_results.log"
# ----------------------------

# Setup logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

print_lock = threading.Lock()
port_queue = queue.Queue()


def scan_port(target, port):
    """Scan a single TCP port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)

        result = sock.connect_ex((target, port))

        with print_lock:
            if result == 0:
                print(f"[OPEN]     Port {port}")
                logging.info(f"OPEN Port {port}")
            elif result == 111:
                print(f"[CLOSED]   Port {port}")
                logging.info(f"CLOSED Port {port}")
            else:
                print(f"[FILTERED] Port {port}")
                logging.info(f"FILTERED Port {port}")

        sock.close()

    except socket.timeout:
        with print_lock:
            print(f"[TIMEOUT]  Port {port}")
            logging.info(f"TIMEOUT Port {port}")

    except Exception as e:
        with print_lock:
            print(f"[ERROR] Port {port}: {e}")
            logging.error(f"ERROR Port {port}: {e}")


def worker(target):
    """Thread worker function"""
    while not port_queue.empty():
        port = port_queue.get()
        scan_port(target, port)
        port_queue.task_done()


def main():
    print("\n===== TCP Port Scanner =====\n")

    target = input("Enter target host/IP: ")
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("❌ Hostname could not be resolved.")
        return

    print(f"\nScanning {target_ip} from port {start_port} to {end_port}")
    print("-" * 50)

    start_time = datetime.now()

    # Fill queue with ports
    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    # Create threads
    threads = []
    for _ in range(THREAD_COUNT):
        thread = threading.Thread(target=worker, args=(target_ip,))
        thread.daemon = True
        thread.start()
        threads.append(thread)

    # Wait for completion
    port_queue.join()

    end_time = datetime.now()
    print("-" * 50)
    print(f"Scan completed in: {end_time - start_time}")
    print(f"Results saved to: {LOG_FILE}")


if _name_ == "_main_":
    main()