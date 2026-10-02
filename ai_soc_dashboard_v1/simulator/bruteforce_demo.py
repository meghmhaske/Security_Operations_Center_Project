import time
import requests
from datetime import datetime, timezone

API = "http://127.0.0.1:8000/events"
ATTACKER_IP = "10.10.10.50"
TARGET_IP = "10.10.10.10"

def send(event_type, **kwargs):
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_type": "simulator",
        "event_type": event_type,
        "source_ip": ATTACKER_IP,
        "destination_ip": TARGET_IP,
        **kwargs,
    }
    r = requests.post(API, json=payload, timeout=5)
    print(event_type, "=>", r.json())
    time.sleep(0.4)

print("\n=== SAFE LOCAL ACCOUNT-COMPROMISE SIMULATION ===\n")

for i in range(8):
    send(
        "failed_login",
        username=["admin", "root", "test", "user"][i % 4],
        destination_port=22,
        protocol="TCP",
        status="failed",
    )

send("successful_login", username="admin", destination_port=22, protocol="TCP", status="success")
send("privilege_escalation", username="admin", protocol="LOCAL", status="success")
send("data_transfer", username="admin", protocol="TCP", bytes_transferred=5_000_000, status="success")

print("\nSimulation complete.")
