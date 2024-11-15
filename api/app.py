from flask import Flask, jsonify
import subprocess
import threading
import time
from datetime import datetime, timedelta
import json
import os

app = Flask(__name__)

# Store blacklisted IPs with their expiry time
BLACKLIST_FILE = '/var/lib/cloudflare-warp/blacklist.json'
blacklisted_ips = {}

def load_blacklist():
    global blacklisted_ips
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'r') as f:
            blacklisted_ips = json.load(f)
    
    # Convert string timestamps back to datetime objects
    blacklisted_ips = {ip: datetime.fromisoformat(timestamp) 
                      for ip, timestamp in blacklisted_ips.items()}

def save_blacklist():
    # Convert datetime objects to ISO format strings for JSON serialization
    blacklist_save = {ip: timestamp.isoformat() 
                     for ip, timestamp in blacklisted_ips.items()}
    with open(BLACKLIST_FILE, 'w') as f:
        json.dump(blacklist_save, f)

def cleanup_blacklist():
    while True:
        now = datetime.now()
        expired = [ip for ip, timestamp in blacklisted_ips.items() 
                  if now > timestamp]
        
        for ip in expired:
            try:
                subprocess.run(['sudo', 'iptables', '-D', 'OUTPUT', '-d', ip, '-j', 'DROP'])
                del blacklisted_ips[ip]
                print(f"Removed {ip} from blacklist")
            except Exception as e:
                print(f"Error removing {ip} from iptables: {e}")
        
        save_blacklist()
        time.sleep(300)  # Check every 5 minutes

def get_current_ip():
    try:
        result = subprocess.run(['curl', '-s', 'https://cloudflare.com/cdn-cgi/trace'], 
                              capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if line.startswith('ip='):
                return line[3:]
    except Exception as e:
        print(f"Error getting current IP: {e}")
        return None

@app.route('/rotate', methods=['POST'])
def rotate_ip():
    old_ip = get_current_ip()
    if old_ip:
        # Add current IP to blacklist
        try:
            subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-d', old_ip, '-j', 'DROP'])
            blacklisted_ips[old_ip] = datetime.now() + timedelta(hours=24)
            save_blacklist()
        except Exception as e:
            print(f"Error blacklisting IP {old_ip}: {e}")
    
    # Disconnect and reconnect WARP
    try:
        subprocess.run(['warp-cli', 'disconnect'], check=True)
        time.sleep(1)
        subprocess.run(['warp-cli', 'connect'], check=True)
        time.sleep(2)
        
        new_ip = get_current_ip()
        return jsonify({
            'success': True,
            'old_ip': old_ip,
            'new_ip': new_ip
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/status', methods=['GET'])
def get_status():
    current_ip = get_current_ip()
    return jsonify({
        'current_ip': current_ip,
        'blacklisted_ips': {ip: timestamp.isoformat() 
                           for ip, timestamp in blacklisted_ips.items()}
    })

def main():
    load_blacklist()
    cleanup_thread = threading.Thread(target=cleanup_blacklist, daemon=True)
    cleanup_thread.start()
    app.run(host='0.0.0.0', port=8080)

if __name__ == '__main__':
    main() 