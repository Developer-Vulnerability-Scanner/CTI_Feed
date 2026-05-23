import os
import time
import psycopg2
from pathlib import Path

DB_CONFIG = {
    "host": "cti_db", # Resolves to the database container name on cti_network
    "port": "5432",
    "database": "CTI_Feed",
    "user": "postgres",
    "password": os.getenv("DB_PASSWORD")
}

OUTPUT_FILE = Path("/etc/modsecurity/shared/ip_blocklist.txt")

def export_active_iocs():
    try:
        # Create output path if it doesn't exist
        OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        
        conn = psycopg2.connect(**DB_CONFIG)
        with conn.cursor() as cur:
            # Query for active IPs
            query = "SELECT ioc_value FROM prioritized_iocs WHERE status = 'active' AND ioc_type = 'ip:port';"
            cur.execute(query)
            rows = cur.fetchall()

        ips = {row[0].split(':')[0] for row in rows}

        # Write out to the shared volume
        with open(OUTPUT_FILE, 'w') as f:
            for ip in ips:
                f.write(f"{ip}\n")
        
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Success: Synchronized {len(ips)} IPs with WAF.")

    except Exception as e:
        print(f"Sync failed: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    # Continuous loop simulating cron within the container
    while True:
        export_active_iocs()
        # Wait 1 hour (3600 seconds) before the next sync
        time.sleep(3600)