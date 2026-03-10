import os
import re
import json
import logging
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, session, redirect, url_for

# ============================================================================
# CONFIGURATION & LOGGING
# ============================================================================

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)

# Path settings
BASE_DIR = '/opt/universal-signal-webhook'
LOG_PATH = '/var/log/universal-signal-webhook.log'
CONFIG_PATH = os.path.join(BASE_DIR, 'config.json')
TECH_PATH = os.path.join(BASE_DIR, 'technicians.json')
CACHE_PATH = os.path.join(BASE_DIR, 'cache.json')
ENDPOINTS_PATH = os.path.join(BASE_DIR, 'endpoints.json')

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Default Throttle Settings (in hours)
ZABBIX_THROTTLE_HOURS = 4
GRAFANA_THROTTLE_HOURS = 4
OBSERVIUM_THROTTLE_HOURS = 4

# Network Settings
WEBHOOK_HOST = '0.0.0.0'
WEBHOOK_PORT = 5000

# Groups mapping
GROUPS = {
    'grafana': 'your_grafana_group_id',
    'zabbix': 'your_zabbix_group_id',
    'observium': 'your_observium_group_id',
    'glpi': 'your_glpi_group_id'
}

CUSTOM_ENDPOINTS = {}
ALERT_CACHE = {}

# ============================================================================
# HELPERS
# ============================================================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def verify_password(username, password):
    # Place your actual authentication logic here
    return username == 'admin' and password == 'sajan@1234'

def save_config():
    config = {
        'zabbix_throttle_hours': ZABBIX_THROTTLE_HOURS,
        'grafana_throttle_hours': GRAFANA_THROTTLE_HOURS,
        'observium_throttle_hours': OBSERVIUM_THROTTLE_HOURS
    }
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=4)

def load_config():
    global ZABBIX_THROTTLE_HOURS, GRAFANA_THROTTLE_HOURS, OBSERVIUM_THROTTLE_HOURS
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            config = json.load(f)
            ZABBIX_THROTTLE_HOURS = config.get('zabbix_throttle_hours', 4)
            GRAFANA_THROTTLE_HOURS = config.get('grafana_throttle_hours', 4)
            OBSERVIUM_THROTTLE_HOURS = config.get('observium_throttle_hours', 4)

def load_cache():
    global ALERT_CACHE
    if os.path.exists(CACHE_PATH):
        try:
            with open(CACHE_PATH, 'r') as f:
                ALERT_CACHE = json.load(f)
        except:
            ALERT_CACHE = {}

def save_cache():
    with open(CACHE_PATH, 'w') as f:
        json.dump(ALERT_CACHE, f)

def load_custom_endpoints():
    global CUSTOM_ENDPOINTS
    if os.path.exists(ENDPOINTS_PATH):
        try:
            with open(ENDPOINTS_PATH, 'r') as f:
                CUSTOM_ENDPOINTS = json.load(f)
        except:
            CUSTOM_ENDPOINTS = {}

def save_custom_endpoints():
    with open(ENDPOINTS_PATH, 'w') as f:
        json.dump(CUSTOM_ENDPOINTS, f)

def get_technician_number(name):
    if not os.path.exists(TECH_PATH): return None
    try:
        with open(TECH_PATH, 'r') as f:
            techs = json.load(f)
            # Find name in keys (case-insensitive)
            for k, v in techs.items():
                if name.lower() in k.lower():
                    return v
    except:
        return None
    return None

def should_send_alert(fingerprint, host, throttle_hours):
    now = datetime.now()
    key = f"{fingerprint}|{host}"
    
    if key in ALERT_CACHE:
        last_sent = datetime.fromisoformat(ALERT_CACHE[key])
        if now < last_sent + timedelta(hours=throttle_hours):
            logger.info(f"🚫 Throttled: {fingerprint}|{host} (Sent: {last_sent})")
            return False
            
    ALERT_CACHE[key] = now.isoformat()
    save_cache()
    return True

def send_to_signal_group(group_id, message):
    # Integration with Signal-CLI-REST-API
    # In a real setup, this would be a requests.post call
    logger.info(f"📤 Sent to Signal successfully ({group_id}): {message[:50]}...")
    return True

def register_dynamic_webhook(name, group_id):
    # Dummy function for dynamic registration logic
    pass

# ============================================================================
# FORMATTERS
# ============================================================================

def format_grafana_alert(data):
    alerts = data.get('alerts', [])
    messages = [f"📊 Grafana Webhook: {len(alerts)} alerts"]
    for alert in alerts:
        messages.append(f"• {alert.get('labels', {}).get('alertname')}: {alert.get('status')}")
    return "\n".join(messages)

def format_zabbix_alert(data):
    return f"🌐 Zabbix Alert:\n{data.get('subject', 'No Subject')}\n{data.get('message', 'No Message')}"

def format_observium_alert(alert_data):
    try:
        title = (alert_data.get('ALERT_NAME') or 
                 alert_data.get('alert_name') or 
                 alert_data.get('ALERT_MESSAGE') or 
                 'System Alert')
        device = (alert_data.get('DEVICE_HOSTNAME') or 
                  alert_data.get('hostname') or 
                  alert_data.get('host') or 
                  'Unknown Device')
        ip = alert_data.get('DEVICE_IP') or 'N/A'
        
        messages = []
        # Extract severity
        severity = (alert_data.get('SEVERITY') or
                   alert_data.get('severity') or
                   alert_data.get('ALERT_SEVERITY') or
                   alert_data.get('level') or
                   'crit')
        
        messages.append(f"🏷️ Alert » {title}")
        host_line = f"🖥️ Host  » {device}"
        if ip and ip != 'N/A' and ip != device: 
            host_line += f" ({ip})"
        messages.append(host_line)
        
        messages.append(f"📊 Rank  » {str(severity).upper()}")
        messages.append("\n━━━━━━━━━━━━━━━━━━")
        messages.append(f"⏰ {datetime.now().strftime('%Y-%m-%d  |  %H:%M')}")
        messages.append("━━━━━━━━━━━━━━━━━━")
        return "\n".join(messages)
    except Exception as e:
        logger.error(f"Observium format error: {e}, Data: {alert_data}")
        return f"⚠️ Observium Error: {e}"

def format_glpi_alert(data):
    # Basic GLPI formatter
    return f"📁 GLPI Update: {json.dumps(data)}"

def format_glpi_direct_alert(alert_data):
    try:
        # Check if the entire message is hidden in a dictionary key (GLPI unstructured format)
        raw_text = ""
        if isinstance(alert_data, dict):
            for k in alert_data.keys():
                if "Ticket ID" in str(k) and "Assigned to" in str(k):
                    raw_text = str(k)
                    break
        
        if raw_text:
            # Parse from raw text using regex
            ticket_id = re.search(r"Ticket ID: (.*)", raw_text)
            title = re.search(r"Title: (.*)", raw_text)
            status = re.search(r"Status: (.*)", raw_text)
            assigned = re.search(r"Assigned to: (.*)", raw_text)
            
            ticket_id = ticket_id.group(1).strip() if ticket_id else "N/A"
            title = title.group(1).strip() if title else "N/A"
            status = status.group(1).strip() if status else "N/A"
            assigned_str = assigned.group(1).strip() if assigned else "N/A"
        else:
            # Fallback to standard fields
            ticket_id = alert_data.get('id', alert_data.get('ticket_id', 'N/A'))
            title = alert_data.get('name', alert_data.get('title', 'N/A'))
            status = alert_data.get('status', 'N/A')
            assigned_str = alert_data.get('assigned_to', alert_data.get('technician_username', 'N/A'))
        
        # Simple HTML tag removal if GLPI sends HTML
        title = re.sub('<[^<]+?>', '', str(title))
        
        messages = [
            "The ticket you're involved in has been updated.",
            "",
            f"🔹 Ticket ID: {ticket_id}",
            f"🔹 Title: {title}",
            f"🔹 Status: {status}",
            f"🔹 Assigned to: {assigned_str}",
            "",
            "Regards,",
            "CISAI IT SUPPORT"
        ]
        return "\n".join(messages), assigned_str
    except Exception as e:
        logger.error(f"Error formatting direct GLPI alert: {e}")
        return f"⚠️ Direct GLPI Alert Error", "N/A"

# ============================================================================
# ROUTES
# ============================================================================

@app.route('/webhook/grafana', methods=['POST'])
def webhook_grafana():
    data = request.get_json(force=True, silent=True)
    if not data: return jsonify({'status': 'error'}), 400
    
    logger.info(f"📊 Received Grafana alert: {json.dumps(data)[:200]}...")
    
    filtered = []
    for alert in data.get('alerts', []):
        fp = f"{alert.get('labels', {}).get('alertname')}|{alert.get('labels', {}).get('instance')}"
        if should_send_alert(fp, alert.get('labels', {}).get('instance'), throttle_hours=GRAFANA_THROTTLE_HOURS):
            filtered.append(alert)
    if not filtered: return jsonify({'status': 'throttled'}), 200
    data['alerts'] = filtered
    send_to_signal_group(GROUPS['grafana'], format_grafana_alert(data))
    return jsonify({'status': 'successful'}), 200

@app.route('/webhook/zabbix', methods=['POST'])
def webhook_zabbix():
    data = request.get_json(force=True, silent=True)
    if not data: return jsonify({'status': 'error'}), 400
    
    logger.info(f"🌐 Received Zabbix Alert: {json.dumps(data)[:200]}...")
    
    # Extraction for Throttling
    full_message = str(data.get('message', data.get('body', '')))
    subject = str(data.get('subject', data.get('title', '')))
    
    # Detect if recovery (Recoveries bypass throttle)
    is_resolved = (
        any(k in subject.upper() for k in ['RESOLVED', 'RECOVERED', 'OK', 'UP']) or
        'Resolved:' in full_message
    )
    
    if not is_resolved:
        # Get Fingerprint (Trigger + Host)
        host_match = re.search(r"Host:\s*([^\s\r\n]+)", full_message, re.IGNORECASE)
        host = host_match.group(1).strip() if host_match else data.get('host', 'N/A')
        
        prob_match = re.search(r"Problem:\s*(.*)", full_message, re.IGNORECASE)
        trigger = prob_match.group(1).strip() if prob_match else subject
        
        fingerprint = re.sub(r'^[🚨✅🖥️📊🟠🟡⚠️ℹ️🔴⏰🆔ID: ]+', '', str(trigger)).strip()
        
        if not should_send_alert(fingerprint, host, throttle_hours=ZABBIX_THROTTLE_HOURS):
            return jsonify({'status': 'throttled'}), 200

    send_to_signal_group(GROUPS['zabbix'], format_zabbix_alert(data))
    return jsonify({'status': 'successful'}), 200

@app.route('/webhook/observium', methods=['POST'])
def webhook_observium():
    # Try JSON first, then Form, then args
    data = request.get_json(force=True, silent=True) or request.form.to_dict() or request.args.to_dict()
    
    if not data:
        # If still empty, log the raw payload for debugging
        raw_payload = request.get_data().decode('utf-8', errors='ignore')
        logger.warning(f"⚠️ Empty Observium Data. Raw payload: {raw_payload[:500]}")
        return jsonify({'status': 'successful'}), 200
    
    logger.info(f"📊 Received Observium alert ({'JSON' if request.is_json else 'Form'}): {json.dumps(data)[:300]}...")
    
    # Handle state/status for Throttling
    state = str(data.get('ALERT_STATE', data.get('alert_state', 'UNKNOWN'))).upper()
    is_recovered = state in ['RECOVER', 'RECOVERY', 'OK', 'RESOLVED']
    
    if not is_recovered:
        # Get Fingerprint (Alert Name + Device)
        title = (data.get('ALERT_NAME') or data.get('alert_name') or data.get('ALERT_MESSAGE') or 'System Alert')
        device = (data.get('DEVICE_HOSTNAME') or data.get('hostname') or data.get('host') or 'Unknown Device')
        fingerprint = f"{title}|{device}"
        
        if not should_send_alert(fingerprint, device, throttle_hours=OBSERVIUM_THROTTLE_HOURS):
            return jsonify({'status': 'throttled'}), 200

    send_to_signal_group(GROUPS['observium'], format_observium_alert(data))
    return jsonify({'status': 'successful'}), 200

@app.route('/webhook/glpi', methods=['POST'])
def webhook_glpi():
    data = request.get_json(force=True, silent=True) or request.form.to_dict()
    send_to_signal_group(GROUPS['glpi'], format_glpi_alert(data))
    return jsonify({'status': 'successful'}), 200

@app.route('/webhook/glpi-direct', methods=['POST'])
def webhook_glpi_direct():
    data = request.get_json(force=True, silent=True) or request.form.to_dict()
    logger.info(f"📥 Received GLPI Direct request")
    
    # Parse the message and get the assigned list
    message, assigned_str = format_glpi_direct_alert(data)
    
    if assigned_str == "N/A":
        logger.info(f"🔇 No technician found in payload.")
        return jsonify({"status": "ignored", "reason": "no_technician_field"}), 200

    # Split multiple technicians (e.g. "Krishnanunni A, Abhishek D")
    tech_names = [name.strip() for name in assigned_str.replace(",", " ").split() if name.strip()]
    
    # Handle the case where full names might be used as keys (e.g. "Krishnanunni A")
    full_names = [name.strip() for name in assigned_str.split(",") if name.strip()]
    
    sent_count = 0
    for tech_name in (full_names + tech_names):
        tech_phone = get_technician_number(tech_name)
        if tech_phone:
            logger.info(f"👤 Ticket assigned to {tech_name}. Sending to private Signal: {tech_phone}")
            send_to_signal_group(tech_phone, message)
            sent_count += 1
            
    if sent_count > 0:
        return jsonify({"status": "successful", "sent_to_count": sent_count}), 200
    else:
        logger.info(f"🔇 No mapping found for technicians: {assigned_str}")
        return jsonify({"status": "ignored", "reason": "no_technician_mapped"}), 200

# ============================================================================
# AUTHENTICATION ROUTES
# ============================================================================

@app.route('/')
@app.route('/login')
def login_page():
    """Serve the login page"""
    try:
        with open(os.path.join(BASE_DIR, 'login.html'), 'r') as f:
            return f.read()
    except:
        return "<h1>Login page not found</h1>", 404

@app.route('/api/login', methods=['POST'])
def api_login():
    """Handle login requests"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        remember = data.get('remember', False)
        
        if not username or not password:
            return jsonify({'success': False, 'message': 'Username and password required'}), 400
        
        if verify_password(username, password):
            session['logged_in'] = True
            session['username'] = username
            session['login_time'] = datetime.now().isoformat()
            
            if remember:
                session.permanent = True
            
            logger.info(f"✅ Successful login: {username}")
            
            # Generate simple token
            token = secrets.token_urlsafe(32)
            session['token'] = token
            
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'token': token,
                'username': username
            }), 200
        else:
            logger.warning(f"❌ Failed login attempt: {username}")
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
            
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'success': False, 'message': 'Server error'}), 500

@app.route('/api/logout', methods=['POST'])
def api_logout():
    """Handle logout requests"""
    username = session.get('username', 'unknown')
    session.clear()
    logger.info(f"🚪 Logout: {username}")
    return jsonify({'success': True, 'message': 'Logged out successfully'}), 200

@app.route('/api/verify', methods=['GET'])
def api_verify():
    """Verify if user is logged in"""
    if 'logged_in' in session and session['logged_in']:
        return jsonify({
            'authenticated': True,
            'username': session.get('username')
        }), 200
    return jsonify({'authenticated': False}), 401

@app.route('/dashboard')
@login_required
def dashboard():
    """Serve the live monitoring dashboard (protected)"""
    try:
        with open(os.path.join(BASE_DIR, 'dashboard.html'), 'r') as f:
            return f.read()
    except:
        return "<h1>Dashboard file not found</h1>", 404

# ============================================================================
# API ENDPOINTS (DASHBOARD)
# ============================================================================

@app.route('/api/monitoring', methods=['GET'])
@login_required
def api_monitoring():
    """Main API for dashboard statistics and logs (protected)"""
    try:
        data = {
            'stats': {'grafana': 0, 'zabbix': 0, 'observium': 0, 'glpi': 0, 'sent': 0, 'throttled': 0},
            'messages': [],
            'throttled': [],
            'logs': [],
            'custom_endpoints': CUSTOM_ENDPOINTS
        }
        
        if not os.path.exists(LOG_PATH):
            return jsonify(data)

        with open(LOG_PATH, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        today_date = datetime.now().strftime('%Y-%m-%d')
        relevant_lines = [l for l in lines[-1500:] if today_date in l]
        
        last_alerts = {}

        for line in relevant_lines:
            try:
                parts = line.split(' - ', 2)
                if len(parts) < 3: continue
                
                level = parts[1].strip()
                message = parts[2].strip()
                timestamp = parts[0].strip()
                time_only = timestamp.split(' ')[1].split(',')[0] if ' ' in timestamp else timestamp

                # Extract Source & Content
                src = None
                content = None

                if 'Grafana alert' in message:
                    data['stats']['grafana'] += 1
                    src = "Grafana"
                    m = re.search(r'"alertname":\s*"([^"]+)"', message)
                    content = m.group(1) if m else "Disk/Server Alert"
                
                elif 'Zabbix Alert' in message:
                    data['stats']['zabbix'] += 1
                    src = "Zabbix NMS"
                    if 'Problem:' in message:
                        content = message.split('Problem:')[1].split('\\n')[0].split('\\r')[0].strip()
                    else:
                        content = "System Issue"
                
                elif 'Observium alert' in message:
                    data['stats']['observium'] += 1
                    src = "Observium"
                    m = re.search(r'"ALERT_MESSAGE":\s*"([^"]+)"', message)
                    content = m.group(1) if m else "Network Alert"
                
                elif 'CISAI GLPI' in message:
                    data['stats']['glpi'] += 1
                    src = "GLPI"
                    content = "Helpdesk Ticket"

                if src and content: last_alerts[src] = content

                if 'Sent to Signal successfully' in message:
                    data['stats']['sent'] += 1
                    origin = "Signal"
                    note = "System Notification"
                    if last_alerts: origin, note = list(last_alerts.items())[-1]
                    
                    data['messages'].append({
                        'time': time_only,
                        'source': origin,
                        'content': note,
                        'group': 'Alert Group'
                    })

                if '🚫 Throttled:' in message:
                    data['stats']['throttled'] += 1
                    alert_part = message.split('🚫 Throttled:')[1].strip()
                    data['throttled'].append({
                        'time': time_only,
                        'source': 'System',
                        'alert': alert_part,
                        'reason': 'Blocked duplicate'
                    })

                status = 'info'
                if 'ERROR' in level or 'Error' in message: status = 'error'
                elif 'WARNING' in level or 'Throttled' in message: status = 'warning'
                elif 'successfully' in message.lower(): status = 'success'
                
                data['logs'].append({ 'time': time_only, 'level': status, 'message': message[:150] })
            except: continue
            
        data['messages'] = data['messages'][::-1][:20]
        data['throttled'] = data['throttled'][::-1][:15]
        data['logs'] = data['logs'][::-1][:50]
        
        return jsonify(data)
    except Exception as e:
        logger.error(f"Monitoring error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/endpoints/create', methods=['POST'])
@login_required
def create_endpoint():
    """Create a new dynamic webhook endpoint"""
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        group_id = data.get('group_id', '').strip()
        if not name or not group_id: return jsonify({'success': False, 'message': 'Name and Group ID required'}), 400
        
        name = re.sub(r'[^a-zA-Z0-9]', '_', name)
        CUSTOM_ENDPOINTS[name] = group_id
        save_custom_endpoints()
        
        return jsonify({'success': True, 'message': f'Endpoint /webhook/custom/{name.lower()} created!'}), 200
    except Exception as e:
        logger.error(f"Create endpoint error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/config/throttle', methods=['GET'])
@login_required
def get_throttle_config():
    return jsonify({
        'success': True,
        'config': {
            'zabbix_throttle_hours': ZABBIX_THROTTLE_HOURS,
            'grafana_throttle_hours': GRAFANA_THROTTLE_HOURS,
            'observium_throttle_hours': OBSERVIUM_THROTTLE_HOURS
        }
    }), 200

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'}), 200

if __name__ == '__main__':
    load_config()
    load_cache()
    load_custom_endpoints()
    app.run(host=WEBHOOK_HOST, port=WEBHOOK_PORT)
