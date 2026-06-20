import os
import requests
import psycopg2
from psycopg2.extras import execute_batch
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

# ThreatFox
THREATFOX_EXPORT_URL = "https://threatfox.abuse.ch/export/json/recent/"

# AlienVault
ALIENVAULT_API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY")

DB_PASS = os.getenv("DB_PASSWORD")
DB_CONFIG = {
    "host": "localhost",
    "port": "5432",
    "database": "CTI_Feed",
    "user": "postgres",
    "password": DB_PASS
}

# Prioritization Settings
MIN_CONFIDENCE = 75
TARGET_THREATS = ['botnet_cc', 'payload_delivery'] 
TARGET_AV_TYPES = ['IPv4', 'domain', 'hostname', 'url', 'FileHash-SHA256'] 
MAX_IOC_RECORDS = 100000  # Storage limits

def connect_to_db():
    try:
        return psycopg2.connect(**DB_CONFIG)
    except Exception as e:
        print(f"Connection failed: {e}")
        return None

def setup_smart_table(conn):
    query = """
    CREATE TABLE IF NOT EXISTS prioritized_iocs (
        id SERIAL PRIMARY KEY,
        source VARCHAR(50) NOT NULL,
        ioc_value TEXT NOT NULL UNIQUE,
        ioc_type VARCHAR(50),
        threat_type VARCHAR(100),
        malware_name TEXT,
        confidence_level INT,
        status VARCHAR(20) DEFAULT 'active',
        first_seen TIMESTAMP,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    with conn.cursor() as cur:
        cur.execute(query)
        conn.commit()
        print("Prioritized table ready.")

def fetch_threatfox():
    print(f"Fetching and filtering ThreatFox Export Data (Conf > {MIN_CONFIDENCE})...")
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 CTI-Pipeline'
    }
    
    try:
        response = requests.get(THREATFOX_EXPORT_URL, headers=headers, timeout=45)
        
        if response.status_code != 200:
            print(f"ThreatFox Export server returned status: {response.status_code}")
            return []
            
        data = response.json()
        normalized_records = []
        
        for ioc_id, item_list in data.items():
            if not item_list or not isinstance(item_list, list):
                continue
                
            item = item_list[0]
            
            confidence = int(item.get('confidence_level', 0))
            threat_type = item.get('threat_type')
            
            if confidence >= MIN_CONFIDENCE and threat_type in TARGET_THREATS:
                date_str = item.get('first_seen', '')
                dt = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S') if date_str else datetime.now()
                
                ioc_val = item.get('ioc') or item.get('ioc_value')
                
                if not ioc_val:
                    continue
                
                normalized_records.append((
                    'ThreatFox',
                    ioc_val,
                    item.get('ioc_type'),
                    threat_type,
                    item.get('malware_printable'),
                    confidence,
                    dt
                ))
                
        print(f"Successfully processed {len(normalized_records)} ThreatFox records from export dataset.")
        return normalized_records

    except Exception as e:
        print(f"ThreatFox Export Parser Error: {e}")
        return []

def fetch_alienvault():
    print("Fetching and filtering AlienVault OTX...")
    headers = {'X-OTX-API-KEY': ALIENVAULT_API_KEY}
    
    try:
        response = requests.get(ALIENVAULT_API_URL, headers=headers, timeout=30)
        if response.status_code != 200:
            print(f"AlienVault API returned error status: {response.status_code}")
            return []
            
        data = response.json()
        pulses = data.get('results', [])
        normalized_records = []

        for pulse in pulses:
            indicators = pulse.get('indicators', [])
            pulse_name = pulse.get('name', 'Unknown Pulse')
            
            for item in indicators:
                if item.get('type') in TARGET_AV_TYPES:
                    date_str = item.get('created', '')[:19]
                    dt = datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S') if date_str else datetime.now()
                    
                    normalized_records.append((
                        'AlienVault',
                        item.get('indicator'),
                        item.get('type'),
                        'community_pulse',
                        pulse_name,  
                        80,  
                        dt
                    ))
        
        print(f"Successfully processed {len(normalized_records)} AlienVault records.")
        return normalized_records
    except Exception as e:
        print(f"AlienVault API Error: {e}")
        return []

def upsert_prioritized_data(conn, combined_records):
    if not combined_records: 
        return

    query = """
    INSERT INTO prioritized_iocs (
        source, ioc_value, ioc_type, threat_type, malware_name, confidence_level, first_seen
    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (ioc_value) DO UPDATE SET
        confidence_level = EXCLUDED.confidence_level,
        last_updated = CURRENT_TIMESTAMP;
    """

    with conn.cursor() as cur:
        execute_batch(cur, query, combined_records)
        conn.commit()
        print(f"Database updated with {len(combined_records)} total records from active feeds.")


def cleanup_stale_data(conn):
    """
    Handles data eviction based on age, status, and maximum row limits.
    """
    try:
        with conn.cursor() as cur:
            # Hard delete anything marked 'expired' or untouched for over 14 days
            purge_query = """
            DELETE FROM prioritized_iocs 
            WHERE status = 'expired' 
               OR last_updated < NOW() - INTERVAL '14 days';
            """
            cur.execute(purge_query)
            deleted_stale = cur.rowcount
            print(f"Purged {deleted_stale} stale/expired records from the database.")

            # Soft-expire active records older than 7 days
            expire_query = """
            UPDATE prioritized_iocs 
            SET status = 'expired' 
            WHERE status = 'active' 
              AND last_updated < NOW() - INTERVAL '7 days';
            """
            cur.execute(expire_query)
            
            # If the database exceeds MAX_IOC_RECORDS, evict the oldest updated items first.
            count_query = "SELECT COUNT(*) FROM prioritized_iocs;"
            cur.execute(count_query)
            current_count = cur.fetchone()[0]

            if current_count > MAX_IOC_RECORDS:
                overflow = current_count - MAX_IOC_RECORDS
                # Delete low confidence/oldest first
                evict_query = """
                DELETE FROM prioritized_iocs 
                WHERE id IN (
                    SELECT id FROM prioritized_iocs 
                    ORDER BY 
                        CASE WHEN threat_type IN ('botnet_cc', 'payload_delivery') THEN 1 ELSE 0 END ASC,
                        confidence_level ASC,
                        last_updated ASC
                    LIMIT %s
                );
                """
                cur.execute(evict_query, (overflow,))
                print(f"Database limit exceeded ({current_count}/{MAX_IOC_RECORDS}). Evicted {cur.rowcount} low-priority records.")

        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Error during database cleanup/eviction: {e}")

def main():
    conn = connect_to_db()
    if not conn: return

    try:
        setup_smart_table(conn)
        
        tf_data = fetch_threatfox()
        av_data = fetch_alienvault()
        
        all_records = tf_data + av_data
        print(f"Total actionable records collected: {len(all_records)}")
        
        upsert_prioritized_data(conn, all_records)
        cleanup_stale_data(conn)
        
    finally:
        conn.close()

if __name__ == "__main__":
    main()