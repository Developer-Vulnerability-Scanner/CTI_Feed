import os
import requests
import psycopg2
from psycopg2.extras import execute_batch
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

# --- Configuration ---
API_URL = "https://threatfox-api.abuse.ch/api/v1/"
API_KEY = os.getenv("THREATFOX_API_KEY")
DB_PASS = os.getenv("DB_PASSWORD")

DB_CONFIG = {
    "host": "localhost",
    "port": "5432",
    "database": "CTI_Feed",
    "user": "postgres",
    "password": DB_PASS
}

# --- Prioritization Settings ---
MIN_CONFIDENCE = 75
TARGET_THREATS = ['botnet_c2', 'payload_delivery'] # Prioritize critical types

def connect_to_db():
    try:
        return psycopg2.connect(**DB_CONFIG)
    except Exception as e:
        print(f"Connection failed: {e}")
        return None

def setup_smart_table(conn):
    query = """
    CREATE TABLE IF NOT EXISTS prioritized_iocs (
        ioc_id INT PRIMARY KEY,
        ioc_value TEXT NOT NULL,
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

def fetch_and_filter():
    print(f"Fetching and filtering data (Conf > {MIN_CONFIDENCE})...")
    
    headers = {'Auth-Key': API_KEY}
    payload = {'query': 'get_iocs', 'days': 1}
    
    try:
        response = requests.post(API_URL, json=payload, headers=headers, timeout=30)
        data = response.json()
        
        if data.get('query_status') != 'ok':
            return []

        raw_list = data.get('data', [])
        
        # --- PRIORITIZATION LOGIC ---
        # 1. Filter by Confidence
        # 2. Filter by Threat Type
        actionable_data = [
            item for item in raw_list
            if item.get('confidence_level', 0) >= MIN_CONFIDENCE
            and item.get('threat_type') in TARGET_THREATS
        ]
        
        print(f"Filtered {len(raw_list)} down to {len(actionable_data)} actionable IOCs.")
        return actionable_data

    except Exception as e:
        print(f"API Error: {e}")
        return []

def upsert_prioritized_data(conn, ioc_list):
    if not ioc_list: return

    query = """
    INSERT INTO prioritized_iocs (
        ioc_id, ioc_value, ioc_type, threat_type, malware_name, confidence_level, first_seen
    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (ioc_id) DO UPDATE SET
        confidence_level = EXCLUDED.confidence_level,
        last_updated = CURRENT_TIMESTAMP;
    """

    records = []
    for item in ioc_list:
        date_str = item.get('first_seen', '').replace(' UTC', '')
        dt = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S') if date_str else datetime.now()
        
        records.append((
            item.get('id'),
            item.get('ioc'),
            item.get('ioc_type'),
            item.get('threat_type'),
            item.get('malware_printable'),
            item.get('confidence_level'),
            dt
        ))

    with conn.cursor() as cur:
        execute_batch(cur, query, records)
        conn.commit()
        print(f"Database updated with {len(records)} high-priority records.")

def cleanup_stale_data(conn):
    query = "UPDATE prioritized_iocs SET status = 'expired' WHERE last_updated < NOW() - INTERVAL '7 days';"
    with conn.cursor() as cur:
        cur.execute(query)
        conn.commit()
        print("Cleaned up stale indicators.")

def main():
    conn = connect_to_db()
    if not conn: return

    try:
        setup_smart_table(conn)
        
        high_priority_data = fetch_and_filter()
        
        upsert_prioritized_data(conn, high_priority_data)
        
        cleanup_stale_data(conn)
        
    finally:
        conn.close()

if __name__ == "__main__":
    main()