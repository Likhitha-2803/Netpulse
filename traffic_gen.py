import sqlite3
import time
import random

def inject_anomaly():
    conn = sqlite3.connect("netpulse.db")
    cursor = conn.cursor()
    print("\n[!] WARNING: INJECTING SYNTHETIC TRAFFIC SPIKE (DDoS Burst)...")

    for i in range(5):
        high_packets = random.randint(2000, 3000)
        high_bytes = high_packets * random.randint(1200, 1500)

        cursor.execute(
            "INSERT INTO traffic_logs (bytes_captured, packet_count) VALUES (?, ?)",
            (high_bytes, high_packets)
        )
        conn.commit()
        print(f"[!] ANOMALY INJECTED [{i+1}/5]: {high_packets} pkts | {high_bytes} bytes")
        time.sleep(1)

    conn.close()
    print("[+] Anomaly injection complete.\n")

if __name__ == "__main__":
    inject_anomaly()
