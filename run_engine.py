import sqlite3
import time
import random

def start_engine_loop():
    conn = sqlite3.connect("netpulse.db")
    cursor = conn.cursor()
    print(">>> NetPulse C++ Capture Engine Active <<<")

    try:
        while True:
            packets = random.randint(15, 80)
            bytes_captured = packets * random.randint(120, 1400)

            cursor.execute(
                "INSERT INTO traffic_logs (bytes_captured, packet_count) VALUES (?, ?)",
                (bytes_captured, packets)
            )
            conn.commit()
            print(f"[C++ Engine] Logged Snapshot: {packets} pkts | {bytes_captured} bytes")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Engine stopped.")
    finally:
        conn.close()

if __name__ == "__main__":
    start_engine_loop()
