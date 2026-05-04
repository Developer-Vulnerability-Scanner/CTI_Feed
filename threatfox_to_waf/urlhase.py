import requests
import psycopg2
from psycopg2 import sql
import json
import time
from datetime import datetime



# urlhause api url
API_URL = "https://urlhaus-api.abuse.ch/v2/files/exports/235466fde7781efd5c687763571da9e9e16912dbc124b3b0/recent.json"

# Database Configuration
DB_HOST = "localhost"
DB_PORT = "5432"
DB_NAME = "CTI_Feed"
DB_USER = "postgres"
DB_PASSWORD = "postgresql"

# Table Configuration
TABLE_NAME = "api_results"


# connecting to db
def connect_to_db():
    
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        print("Successfully connected to PostgreSQL database!")
        return conn
    except Exception as e:
        print(f"Database connection failed: {e}")
        return None

# creating tables
def recreate_table(conn):
    
    drop_table_query = f"DROP TABLE IF EXISTS {TABLE_NAME} CASCADE;"
    
    create_table_query = """
    CREATE TABLE api_results (
        id SERIAL PRIMARY KEY,
        url_id VARCHAR(255),
        dateadded TIMESTAMP,
        url TEXT,
        url_status VARCHAR(50),
        last_online TIMESTAMP,
        threat VARCHAR(255),
        tags TEXT[],
        urlhaus_link TEXT,
        reporter VARCHAR(255),
        response_data JSONB,
        inserted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    
    try:
        with conn.cursor() as cur:
            cur.execute(drop_table_query)
            print(f"Dropped existing table '{TABLE_NAME}' if it existed")
            
            cur.execute(create_table_query)
            conn.commit()
            print(f"Table '{TABLE_NAME}' recreated successfully with correct schema")
            return True
    except Exception as e:
        print(f"Error recreating table: {e}")
        conn.rollback()
        return False


# Fetching all data

def fetch_from_api():
    
    try:
        print(f"Fetching data from: {API_URL}")
        response = requests.get(API_URL, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        
        if isinstance(data, dict):
            print(f"API Response Type: Dictionary with {len(data)} keys")
            
            if len(data) > 0:
                first_key = list(data.keys())[0]
                print(f"Sample URL ID: {first_key}")
                if isinstance(data[first_key], list) and len(data[first_key]) > 0:
                    print(f"Sample data structure: {list(data[first_key][0].keys())}")
            
            total_records = 0
            for url_id, items in data.items():
                if isinstance(items, list):
                    total_records += len(items)
            
            print(f"Successfully fetched {total_records} records across {len(data)} URLs")
            return data
        else:
            print(f"Unexpected data type: {type(data)}")
            return None
        
    except requests.exceptions.RequestException as e:
        print(f"API request failed: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON response: {e}")
        return None


# # fetching the recent 100 ones
# def fetch_from_api(limit=100):
    
#     try:
#         print(f"Fetching data from: {API_URL}")
#         response = requests.get(API_URL, timeout=30)
#         response.raise_for_status()
        
#         data = response.json()
        
#         if isinstance(data, dict):
#             print(f"API Response Type: Dictionary with {len(data)} keys")
            
#             limited_data = {}
#             count = 0
            
#             sorted_keys = sorted(data.keys(), reverse=True)  
            
#             for url_id in sorted_keys:
#                 if count >= limit:
#                     break
                
#                 if isinstance(data[url_id], list):
#                     limited_data[url_id] = data[url_id]
#                     count += 1
            
#             total_records = 0
#             for url_id, items in limited_data.items():
#                 if isinstance(items, list):
#                     total_records += len(items)
            
#             print(f"Limited to {limit} URLs with {total_records} total records")
#             return limited_data
#         else:
#             print(f"Unexpected data type: {type(data)}")
#             return None
        
#     except requests.exceptions.RequestException as e:
#         print(f"API request failed: {e}")
#         return None
#     except json.JSONDecodeError as e:
#         print(f"Failed to parse JSON response: {e}")
#         return None

# inseting fetched data to db
def insert_data_to_db(conn, api_data):
    
    if not api_data:
        print("No data to insert")
        return 0
    
    insert_query = """
    INSERT INTO api_results (
        url_id,
        dateadded,
        url,
        url_status,
        last_online,
        threat,
        tags,
        urlhaus_link,
        reporter,
        response_data
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
    """
    
    inserted_count = 0
    error_count = 0
    
    try:
        with conn.cursor() as cur:
            for url_id, payloads in api_data.items():
                if not isinstance(payloads, list):
                    print(f"Skipping invalid data for ID {url_id}")
                    continue
                
                for item in payloads:
                    try:
                        dateadded = None
                        if item.get('dateadded'):
                            try:
                                date_str = item['dateadded'].replace(' UTC', '')
                                dateadded = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
                            except Exception as e:
                                print(f"Error parsing dateadded for {url_id}: {e}")
                                dateadded = datetime.now()
                        
                        last_online = None
                        if item.get('last_online'):
                            try:
                                date_str = item['last_online'].replace(' UTC', '')
                                last_online = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
                            except Exception as e:
                                print(f"Error parsing last_online for {url_id}: {e}")
                                last_online = datetime.now()
                        
                        values = (
                            url_id,                              
                            dateadded,                           
                            item.get('url'),                     
                            item.get('url_status'),              
                            last_online,                     
                            item.get('threat'),                 
                            item.get('tags', []),               
                            item.get('urlhaus_link'),            
                            item.get('reporter'),               
                            json.dumps(item)                     
                        )
                        
                        cur.execute(insert_query, values)
                        inserted_count += 1
                        
                        if inserted_count % 100 == 0:
                            print(f"Progress: Inserted {inserted_count} records so far...")
                            conn.commit()
                    
                    except Exception as e:
                        error_count += 1
                        print(f"Error inserting record for ID {url_id}: {e}")
                        if error_count == 1:
                            print(f"Problematic data: {json.dumps(item, indent=2)[:500]}")
                        continue
            
            conn.commit()
            print(f"Successfully inserted {inserted_count} records")
            if error_count > 0:
                print(f"Failed to insert {error_count} records")
            
    except Exception as e:
        print(f"Error in insertion process: {e}")
        conn.rollback()
        return 0
    
    return inserted_count

# verfay the data

def verify_data(conn):
    
    try:
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) FROM {TABLE_NAME}")
            count = cur.fetchone()[0]
            print(f"\nTotal records in database: {count}")
            
            if count > 0:
                cur.execute(f"""
                    SELECT threat, COUNT(*) as count 
                    FROM {TABLE_NAME} 
                    GROUP BY threat 
                    ORDER BY count DESC
                """)
                threat_stats = cur.fetchall()
                
                print("\nThreat Statistics:")
                print("-" * 40)
                for threat, cnt in threat_stats[:5]:
                    print(f"  {threat}: {cnt} records")
                
                cur.execute(f"""
                    SELECT url_id, url, threat, dateadded, url_status 
                    FROM {TABLE_NAME} 
                    ORDER BY dateadded DESC 
                    LIMIT 5
                """)
                results = cur.fetchall()
                
                print("\nMost recent entries:")
                print("-" * 100)
                for row in results:
                    url_short = row[1][:60] if row[1] else "None"
                    print(f"ID: {row[0]} | Threat: {row[2]} | Status: {row[4]} | URL: {url_short}... | Added: {row[3]}")
                    
    except Exception as e:
        print(f"Error verifying data: {e}")



def main():
    """Main execution function"""
    
    print("=" * 50)
    print("URLhaus to PostgreSQL Pipeline")
    print("=" * 50)
    
    # db connection
    conn = connect_to_db()
    if not conn:
        return
    
    try:
        if not recreate_table(conn):
            print("Failed to recreate table. Exiting.")
            return
        
        api_data = fetch_from_api()
        
        if api_data:
            inserted = insert_data_to_db(conn, api_data)
            
            # Step 5: Verify the data
            if inserted > 0:
                verify_data(conn)
        else:
            print("No data to process")
        
        print("\nPipeline completed successfully!")
        
    except Exception as e:
        print(f"Pipeline failed: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        if conn:
            conn.close()
            print("Database connection closed")


if __name__ == "__main__":
    main()