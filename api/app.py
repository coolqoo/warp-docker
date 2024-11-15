from flask import Flask, jsonify, request, abort
import subprocess
import threading
import time
from datetime import datetime, timedelta
import json
import os
from functools import wraps

app = Flask(__name__)

# 配置
API_KEY = os.getenv('API_KEY')
BLACKLIST_FILE = '/var/lib/cloudflare-warp/blacklist.json'
PREFER_IPV4 = os.getenv('PREFER_IPV4', 'true').lower() == 'true'
blacklisted_ips = {}

# API 密钥验证装饰器
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if API_KEY:
            auth_header = request.headers.get('X-API-Key')
            if auth_header != API_KEY:
                abort(401)
        return f(*args, **kwargs)
    return decorated_function

def load_blacklist():
    global blacklisted_ips
    if os.path.exists(BLACKLIST_FILE):
        try:
            with open(BLACKLIST_FILE, 'r') as f:
                blacklisted_ips = json.load(f)
            
            # Convert string timestamps back to datetime objects
            blacklisted_ips = {ip: datetime.fromisoformat(timestamp) 
                          for ip, timestamp in blacklisted_ips.items()}
        except Exception as e:
            print(f"Error loading blacklist: {e}")
            blacklisted_ips = {}

def save_blacklist():
    try:
        # Convert datetime objects to ISO format strings for JSON serialization
        blacklist_save = {ip: timestamp.isoformat() 
                         for ip, timestamp in blacklisted_ips.items()}
        with open(BLACKLIST_FILE, 'w') as f:
            json.dump(blacklist_save, f)
    except Exception as e:
        print(f"Error saving blacklist: {e}")

def cleanup_blacklist():
    while True:
        try:
            now = datetime.now()
            expired = [ip for ip, timestamp in blacklisted_ips.items() 
                      if now > timestamp]
            
            for ip in expired:
                try:
                    subprocess.run(['sudo', 'iptables', '-D', 'OUTPUT', '-d', ip, '-j', 'DROP'],
                                 check=True)
                    del blacklisted_ips[ip]
                    print(f"Removed {ip} from blacklist")
                except Exception as e:
                    print(f"Error removing {ip} from iptables: {e}")
            
            if expired:
                save_blacklist()
        except Exception as e:
            print(f"Error in cleanup_blacklist: {e}")
        
        time.sleep(300)  # Check every 5 minutes

def get_current_ip():
    max_retries = 3
    for _ in range(max_retries):
        try:
            result = subprocess.run(
                ['curl', '-s', '--max-time', '10', 'https://cloudflare.com/cdn-cgi/trace'], 
                capture_output=True, text=True, check=True
            )
            for line in result.stdout.split('\n'):
                if line.startswith('ip='):
                    ip = line[3:]
                    # 如果设置了偏好 IPv4，且当前是 IPv6 地址，则重试
                    if PREFER_IPV4 and ':' in ip:
                        time.sleep(1)
                        continue
                    return ip
        except Exception as e:
            print(f"Error getting current IP: {e}")
            time.sleep(1)
    return None

@app.route('/rotate', methods=['POST'])
@require_api_key
def rotate_ip():
    old_ip = get_current_ip()
    if old_ip:
        try:
            subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-d', old_ip, '-j', 'DROP'],
                         check=True)
            blacklisted_ips[old_ip] = datetime.now() + timedelta(hours=24)
            save_blacklist()
        except Exception as e:
            print(f"Error blacklisting IP {old_ip}: {e}")
    
    # Disconnect and reconnect WARP
    try:
        subprocess.run(['warp-cli', 'disconnect'], check=True)
        time.sleep(1)
        subprocess.run(['warp-cli', 'connect'], check=True)
        
        # 等待并多次尝试获取新IP
        for _ in range(5):
            time.sleep(1)
            new_ip = get_current_ip()
            if new_ip and new_ip != old_ip:
                break
        
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
@require_api_key
def get_status():
    current_ip = get_current_ip()
    return jsonify({
        'current_ip': current_ip,
        'blacklisted_ips': {ip: timestamp.isoformat() 
                           for ip, timestamp in blacklisted_ips.items()}
    })

@app.route('/clear-blacklist', methods=['POST'])
@require_api_key
def clear_blacklist():
    try:
        for ip in blacklisted_ips:
            try:
                subprocess.run(['sudo', 'iptables', '-D', 'OUTPUT', '-d', ip, '-j', 'DROP'],
                             check=True)
            except Exception as e:
                print(f"Error removing {ip} from iptables: {e}")
        
        blacklisted_ips.clear()
        save_blacklist()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def main():
    load_blacklist()
    cleanup_thread = threading.Thread(target=cleanup_blacklist, daemon=True)
    cleanup_thread.start()
    app.run(host='0.0.0.0', port=8080)

if __name__ == '__main__':
    main()
