import requests
import threading
import time
import random
import logging
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("attack_simulation.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("AttackSimulation")

TARGET_IP = "127.0.0.1"
ATTACKER_IP = "172.16.46.16"

# Global flag to control attack
attack_running = True

def send_request():
    total_requests = 0
    while attack_running:  # Infinite loop until stopped
        try:
            url = f"http://{TARGET_IP}:8000/analyze_request/{ATTACKER_IP}"
            packet_size = random.randint(500, 3000)
            params = {"packet_size": packet_size}
            response = requests.get(url, params=params, timeout=5)
            total_requests += 1
            if "Blocked" in response.text:
                logger.warning(f"DDoS detected by server for IP {ATTACKER_IP}")
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection Error: {e}. Retrying...")
            time.sleep(1)
        except requests.exceptions.Timeout:
            logger.error(f"Request timed out to {TARGET_IP}")
        except Exception as e:
            logger.error(f"Error: {e}")
        time.sleep(random.uniform(0.005, 0.05))
    logger.info(f"Attack stopped. Total requests sent: {total_requests}")

def stop_attack():
    global attack_running
    while True:
        user_input = input("Type 'stop' to stop the attack: ").strip().lower()
        if user_input == "stop":
            attack_running = False
            logger.info("Stopping attack...")
            # Notify the server that the attack has stopped
            try:
                requests.get(f"http://{TARGET_IP}:8000/stop_attack_signal")
            except Exception as e:
                logger.error(f"Failed to notify server of attack stop: {e}")
            break

if __name__ == "__main__":
    logger.info("Starting attack simulation...")
    threads = []
    for _ in range(10):
        t = threading.Thread(target=send_request)
        t.start()
        threads.append(t)

    # Start a thread to listen for stop command
    stop_thread = threading.Thread(target=stop_attack)
    stop_thread.start()

    # Wait for all attack threads to finish
    for t in threads:
        t.join()
    stop_thread.join()
    logger.info("Attack simulation finished.")s
