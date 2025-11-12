import json
import requests
import os 
from flask import Flask, request, jsonify
from uuid import uuid4
from datetime import datetime
from flask_cors import CORS
# Import Waitress for production serving
from waitress import serve 

# --- CONFIGURATION: JSONBIN.IO CREDENTIALS ---
# These credentials are provided by the user.
JSONBIN_API_KEY = "$2a$10$OWB0wBTxocZeAjW4yY5pyOQwnVSUr5a3bovRM9LZM5NJI8zpiT3eS"
JSONBIN_BIN_ID = "69148aff43b1c97be9a8eebe"

JSONBIN_URL = f"https://api.jsonbin.io/v3/b/{JSONBIN_BIN_ID}" 

# Local cache settings to avoid hitting the jsonbin API on every request
DEVICE_CACHE = {} 
LAST_FETCH_TIME = None
CACHE_TTL_SECONDS = 60 

# --- FLASK APP INITIALIZATION ---
app = Flask(__name__)
# Initialize CORS globally for all routes
CORS(app ,origins=["https://your-frontend-domain.com"]) 

# --- JSONBIN.IO INTERFACE FUNCTIONS ---

def fetch_device_database():
    """Fetches the current device data from jsonbin.io or returns cached data."""
    global DEVICE_CACHE, LAST_FETCH_TIME
    
    now = datetime.now()
    # Simple cache logic
    if DEVICE_CACHE and LAST_FETCH_TIME and (now - LAST_FETCH_TIME).total_seconds() < CACHE_TTL_SECONDS:
        return DEVICE_CACHE
        
    headers = {'X-Master-Key': JSONBIN_API_KEY}
    
    try:
        response = requests.get(JSONBIN_URL, headers=headers)
        response.raise_for_status() 
        
        # JSONBin returns the data under 'record'
        DEVICE_CACHE = response.json().get('record', {})
        LAST_FETCH_TIME = now
        return DEVICE_CACHE
    except requests.exceptions.RequestException as e:
        print(f"CRITICAL ERROR: Failed to fetch data from jsonbin.io: {e}")
        return {} 

def update_device_database(new_data):
    """Updates the entire device data on jsonbin.io by overwriting the bin content (PUT)."""
    global DEVICE_CACHE, LAST_FETCH_TIME
    
    headers = {
        'Content-Type': 'application/json',
        'X-Master-Key': JSONBIN_API_KEY,
        'X-Bin-Versioning': 'false' # Optional, but good for large, frequently updated bins
    }
    try:
        response = requests.put(JSONBIN_URL, json=new_data, headers=headers)
        response.raise_for_status()
        
        DEVICE_CACHE = new_data
        LAST_FETCH_TIME = datetime.now()
        
        return True
    except requests.exceptions.RequestException as e:
        print(f"CRITICAL ERROR: Failed to update data on jsonbin.io: {e}")
        return False

# --- DEVICE INFO EXTRACTION ---

def get_device_info():
    """Extracts device information, prioritizing client-sent IP for accuracy."""
    
    user_agent = request.headers.get('User-Agent', 'Unknown User Agent')
    # Safely get public_ip from JSON payload sent by frontend
    client_ip_from_payload = request.json.get('public_ip') if request.json and isinstance(request.json, dict) else None

    # Prioritize client-sent IP; fallback to server-detected IP (X-Forwarded-For is best in proxied envs)
    remote_ip = client_ip_from_payload or request.headers.get('X-Forwarded-For', request.remote_addr)
    
    # Safely get client_device_id from JSON payload sent by frontend
    client_device_id = request.json.get('client_device_id') if request.json and isinstance(request.json, dict) else None

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
    
    # --- Check A: Unique ID Match (The browser is returning a known ID) ---
    if client_device_id and client_device_id in current_db:
        
        # Update usage statistics and last seen time
        current_db[client_device_id]['verification_count'] = current_db[client_device_id].get('verification_count', 1) + 1
        current_db[client_device_id]['last_seen'] = device_data['timestamp']
        update_device_database(current_db) 
        
        print(f"Check A: ID found ({client_device_id}). Verification FAILED (Duplicate).")
        return jsonify({
            **response_base,
            "status": "failed",
            "message": "Verification failed: Device ID already registered.",
            "device_id": client_device_id,
            "action": "none" 
        }), 200
    
    # --- Check B: Fingerprint Match (Cache Bypass Attempt) ---
    
    fingerprint_match = None
    # Create the current fingerprint signature
    fingerprint_key = f"{device_data['public_ip']} | {device_data['user_agent']}"
    
    for db_device_id, record in current_db.items():
        # Create the stored fingerprint signature
        db_fingerprint_key = f"{record.get('ip_address')} | {record.get('user_agent')}"
        
        if fingerprint_key == db_fingerprint_key:
            fingerprint_match = db_device_id
            break
            
    if fingerprint_match:
        # A device with this fingerprint exists, but the client didn't send an ID (cleared cache).
        # We block access, but tell the client to re-save the existing ID.
        
        current_db[fingerprint_match]['verification_count'] = current_db[fingerprint_match].get('verification_count', 1) + 1
        current_db[fingerprint_match]['last_seen'] = device_data['timestamp']
        current_db[fingerprint_match]['ip_address'] = device_data['public_ip'] 
        update_device_database(current_db) 
        
        print(f"Check B: Fingerprint matched existing ID {fingerprint_match}. Verification FAILED (Re-save ID).")
        return jsonify({
            **response_base,
            "status": "failed",
            "message": "Verification failed: Device fingerprint already registered. Access blocked.",
            "device_id": fingerprint_match, 
            "action": "resave" 
        }), 200

    # --- Check C: No Match Found (New Device) ---
    
    new_device_id = str(uuid4())
    
    storage_data = {
        "device_id": new_device_id,
        "first_seen": device_data['timestamp'],
        "last_seen": device_data['timestamp'],
        "ip_address": device_data['public_ip'],
        "user_agent": device_data['user_agent'],
        "verification_count": 1
    }
    
    current_db[new_device_id] = storage_data
    
    if update_device_database(current_db):
        print(f"Check C: New Device verified and stored: {new_device_id}. Verification SUCCESS.")
    
        # Return the new ID to the frontend for local storage
        return jsonify({
            **response_base,
            "status": "verified",
            "message": "Device successfully verified and registered.",
            "device_id": new_device_id,
            "action": "save" 
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

# --- PRODUCTION STARTUP (Waitress) ---
if __name__ == '__main__':
    # Render provides the port via the environment variable PORT.
    # We use 0.0.0.0 to listen on all interfaces.
    port = int(os.environ.get('PORT', 5000))
    print(f"Starting production server using Waitress on 0.0.0.0:{port}...")
    serve(app, host='0.0.0.0', port=port, threads=10)
        







