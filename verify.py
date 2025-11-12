import json
import requests
from flask import Flask, request, jsonify
from uuid import uuid4
from datetime import datetime
from flask_cors import CORS

# --- CONFIGURATION: JSONBIN.IO CREDENTIALS ---
# Using the credentials provided by the user.
JSONBIN_API_KEY = "$2a$10$OWB0wBTxocZeAjW4yY5pyOQwnVSUr5a3bovRM9LZM5NJI8zpiT3eS"
JSONBIN_BIN_ID = "69148aff43b1c97be9a8eebe"

JSONBIN_URL = f"https://api.jsonbin.io/v3/b/{JSONBIN_BIN_ID}" 

# Dictionary to hold the device data fetched from the bin
# This acts as a cache to avoid fetching the bin on every single request
DEVICE_CACHE = {} 
LAST_FETCH_TIME = None
CACHE_TTL_SECONDS = 60 # Refresh cache every 60 seconds

verify = Flask(__name__)
CORS(verify)
# --- JSONBIN.IO INTERFACE FUNCTIONS ---

def fetch_device_database():
    """
    Fetches the current device data from jsonbin.io or returns cached data.
    """
    global DEVICE_CACHE, LAST_FETCH_TIME
    
    # Simple cache logic: only fetch if cache is empty or expired
    now = datetime.now()
    if DEVICE_CACHE and LAST_FETCH_TIME and (now - LAST_FETCH_TIME).total_seconds() < CACHE_TTL_SECONDS:
        return DEVICE_CACHE
        
    headers = {'X-Master-Key': JSONBIN_API_KEY}
    
    try:
        response = requests.get(JSONBIN_URL, headers=headers)
        response.raise_for_status() 
        
        # Data is under 'record'
        DEVICE_CACHE = response.json().get('record', {})
        LAST_FETCH_TIME = now
        return DEVICE_CACHE
    except requests.exceptions.RequestException as e:
        print(f"CRITICAL ERROR: Failed to fetch data from jsonbin.io: {e}")
        return {} 

def update_device_database(new_data):
    """
    Updates the entire device data on jsonbin.io by overwriting the bin content (PUT).
    Also updates the local cache.
    """
    global DEVICE_CACHE, LAST_FETCH_TIME
    
    headers = {
        'Content-Type': 'application/json',
        'X-Master-Key': JSONBIN_API_KEY,
        'X-Bin-Versioning': 'false' # Ensure no versioning is created for large apps
    }
    try:
        response = requests.put(JSONBIN_URL, json=new_data, headers=headers)
        response.raise_for_status()
        
        # Update local cache upon successful write
        DEVICE_CACHE = new_data
        LAST_FETCH_TIME = datetime.now()
        
        return True
    except requests.exceptions.RequestException as e:
        print(f"CRITICAL ERROR: Failed to update data on jsonbin.io: {e}")
        return False

# --- DEVICE INFO EXTRACTION ---

def get_device_info():
    """
    Extracts device information, prioritizing the IP sent by the frontend for accuracy.
    """
    
    # 1. Get User Agent
    user_agent = request.headers.get('User-Agent', 'Unknown User Agent')
    
    # 2. Get Public IP (Client side is sent in the payload)
    client_ip_from_payload = request.json.get('public_ip') if request.json else None

    # Fallback to server-side detected IP (X-Forwarded-For is best attempt)
    remote_ip = client_ip_from_payload or request.headers.get('X-Forwarded-For', request.remote_addr)

    # 3. Get the client-side ID sent by the browser cache
    client_device_id = request.json.get('client_device_id') if request.json else None

    return {
        "public_ip": remote_ip,
        "user_agent": user_agent,
        "client_id_sent": client_device_id,
        "timestamp": datetime.now().isoformat()
    }

# --- VERIFICATION LOGIC ---

@app.route('/verify-device', methods=['POST'])
def verify_device():
    
    device_data = get_device_info()
    client_device_id = device_data.get('client_id_sent')
    current_db = fetch_device_database()
    
    response_base = {
        "ip_address": device_data['public_ip'],
        "user_agent": device_data['user_agent'],
    }
    
    # --- Check A: Unique ID Match (Primary Verification) ---
    if client_device_id and client_device_id in current_db:
        # A known device is accessing the site again
        
        # Update usage statistics
        current_db[client_device_id]['verification_count'] = current_db[client_device_id].get('verification_count', 1) + 1
        current_db[client_device_id]['last_seen'] = device_data['timestamp']
        
        update_device_database(current_db) # Commit the statistics update
        
        print(f"Check A: ID found ({client_device_id}). Verification FAILED (Duplicate).")
        return jsonify({
            **response_base,
            "status": "failed",
            "message": "Verification failed: Device ID already registered.",
            "device_id": client_device_id,
            "action": "none" # Tell frontend to do nothing with the local ID
        }), 200
    
    # --- Check B: Fingerprint Match (IP + User Agent) - Cache Bypass Check ---
    
    fingerprint_match = None
    fingerprint_key = f"{device_data['public_ip']} | {device_data['user_agent']}"
    
    for db_device_id, record in current_db.items():
        db_fingerprint_key = f"{record.get('ip_address')} | {record.get('user_agent')}"
        
        # Check if the current IP/UA combination matches any existing record
        if fingerprint_key == db_fingerprint_key:
            fingerprint_match = db_device_id
            break
            
    if fingerprint_match:
        # A device with this exact fingerprint already exists, but they didn't send the ID.
        # This means they cleared their cache. We block access but re-issue the old ID.
        
        # Update usage statistics of the matched device
        current_db[fingerprint_match]['verification_count'] = current_db[fingerprint_match].get('verification_count', 1) + 1
        current_db[fingerprint_match]['last_seen'] = device_data['timestamp']
        current_db[fingerprint_match]['ip_address'] = device_data['public_ip'] # Update IP in case it changed slightly
        
        update_device_database(current_db) 
        
        print(f"Check B: Fingerprint matched existing ID {fingerprint_match}. Verification FAILED (Re-save ID).")
        return jsonify({
            **response_base,
            "status": "failed",
            "message": "Verification failed: Device fingerprint already registered. Access blocked.",
            "device_id": fingerprint_match, # Return the old ID
            "action": "resave" # Tell frontend to save this ID
        }), 200

    # --- Check C: No Match Found (New Device) ---
    
    # Generate a unique device ID
    new_device_id = str(uuid4())
    
    # Data to store for this new device
    storage_data = {
        "device_id": new_device_id,
        "first_seen": device_data['timestamp'],
        "last_seen": device_data['timestamp'],
        "ip_address": device_data['public_ip'],
        "user_agent": device_data['user_agent'],
        "verification_count": 1
    }
    
    # Add new device to the database structure
    current_db[new_device_id] = storage_data
    
    # Store the updated database (jsonbin.io PUT logic)
    if update_device_database(current_db):
        print(f"Check C: New Device verified and stored: {new_device_id}. Verification SUCCESS.")
    
        # Return the new ID to the frontend for local storage
        return jsonify({
            **response_base,
            "status": "verified",
            "message": "Device successfully verified and registered.",
            "device_id": new_device_id,
            "action": "save" # Tell frontend to save this new ID
        }), 200
    else:
         return jsonify({
            **response_base,
            "status": "error",
            "message": "Verification failed: Could not save data to database.",
            "device_id": None
        }), 500


@app.route('/device-list', methods=['GET'])
def device_list():
    """Admin route to see what's in the simulated/real database."""
    devices = fetch_device_database()
    return jsonify({
        "total_devices": len(devices),
        "devices": devices
    }), 200

# To run the app, you need to install Flask and requests, then execute it:
# $ pip install Flask requests
# $ export FLASK_APP=app.py
# $ flask run
if __name__ == '__main__':
    # Add CORS headers for the frontend to be able to talk to the backend
    @app.after_request
    def add_cors_headers(response):
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST,GET,OPTIONS')
        return response
        

    app.run(host='0.0.0.0',port=port,debug=True)

