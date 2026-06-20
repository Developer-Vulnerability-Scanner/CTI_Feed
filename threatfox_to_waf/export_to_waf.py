# export_to_waf.py
import os
import subprocess
import psycopg2
from dotenv import load_dotenv

load_dotenv()

DB_PASS = os.getenv("DB_PASSWORD")
DB_CONFIG = {
    "host": "localhost",
    "port": "5432",
    "database": "CTI_Feed",
    "user": "postgres",
    "password": DB_PASS
}

WAF_BLOCKLIST_PATH = "/etc/modsecurity/blocked_ips.data"

def export_threat_intel():
    print("Executing dynamic database-to-WAF CTI feed deployment...")
    
    try:
        # Establish link to  local PostgreSQL CTI_Feed database
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        
        # Pull active indicators that contain IP data elements
        query = """
        SELECT DISTINCT ioc_value 
        FROM prioritized_iocs 
        WHERE status = 'active' 
          AND ioc_type IN ('ip:port', 'IPv4', 'ip');
        """
        cur.execute(query)
        rows = cur.fetchall()
        
        # Clear ports if present (e.g., "185.220.101.5:8080" -> "185.220.101.5")
        blocked_ips = set()
        for row in rows:
            raw_val = row[0]
            if raw_val:
                ip = raw_val.split(':')[0].strip()
                blocked_ips.add(ip)
                
        print(f"Extracted {len(blocked_ips)} unique active threat IPs.")

        if not blocked_ips:
            print("No active malicious IPs found in database. Skipping compilation.")
            cur.close()
            conn.close()
            return

        # Write clean, sorted items out to the ModSecurity text file destination
        with open(WAF_BLOCKLIST_PATH, "w") as out_file:
            for ip in sorted(blocked_ips):
                out_file.write(f"{ip}\n")
                
        print(f"Successfully compiled network blocklist inside {WAF_BLOCKLIST_PATH}")
        
        # Gracefully reload Nginx to push live changes into the worker rules engine
        print("Reloading Nginx engine configurations...")
        subprocess.run(["sudo", "systemctl", "reload", "nginx"], check=True)
        print("WAF threat intel synchronization complete. Core operational.")
        
        cur.close()
        conn.close()
        
    except Exception as e:
        print(f"Pipeline Sync Failure: {e}")

if __name__ == "__main__":
    export_threat_intel()