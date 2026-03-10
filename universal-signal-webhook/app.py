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

# Generic Path settings
BASE_DIR = '/opt/signal-webhook'
LOG_PATH = '/var/log/signal-webhook.log'
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
    'helpdesk': 'your_helpdesk_group_id'
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
    # Dummy authentication for demonstration
    return username == 'admin' and password == 'change_this_password'

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
    # Integration with Signal-CLI-REST-API placeholder
    logger.info(f"📤 Sent to Signal successfully ({group_id}): {message[:50]}...")
    return True

# ============================================================================
# FORMATTERS (Anonymized)
# ============================================================================

def format_grafana_alert(data):
    alerts = data.get('alerts', [])
    messages = [f"📊 Monitoring Update: {len(alerts)} events"]
    for alert in alerts:
        messages.append(f"• {alert.get('labels', {}).get('alertname')}: {alert.get('status')}")
    return "\n".join(messages)

def format_zabbix_alert(data):
    return f"🌐 Network Alert:\n{data.get('subject', 'No Subject')}\n{data.get('message', 'No Message')}"

def format_observium_alert(alert_data):
    try:
        title = (alert_data.get('ALERT_NAME') or alert_data.get('ALERT_MESSAGE') or 'System Alert')
        device = (alert_data.get('DEVICE_HOSTNAME') or alert_data.get('host') or 'Unknown Device')
        ip = alert_data.get('DEVICE_IP') or 'N/A'
        
        messages = [
            f"🏷️ Alert » {title}",
            f"🖥️ Host  » {device} ({ip})",
            f"📊 Rank  » {str(alert_data.get('SEVERITY', 'CRIT')).upper()}",
            "\n━━━━━━━━━━━━━━━━━━",
            f"⏰ {datetime.now().strftime('%H:%M')}",
            "━━━━━━━━━━━━━━━━━━"
        ]
        return "\n".join(messages)
    except Exception as e:
        logger.error(f"Format error: {e}")
        return f"⚠️ Alert Payload Error"

def format_ticket_alert(alert_data):
    try:
        # Handling unstructured key-value pairings from generic helpdesks
        raw_text = ""
        if isinstance(alert_data, dict):
            for k in alert_data.keys():
                if "Ticket ID" in str(k):
                    raw_text = str(k)
                    break
        
        if raw_text:
            ticket_id = re.search(r"Ticket ID: (.*)", raw_text)
            assigned = re.search(r"Assigned to: (.*)", raw_text)
            ticket_id = ticket_id.group(1).strip() if ticket_id else "N/A"
            assigned_str = assigned.group(1).strip() if assigned else "N/A"
        else:
            ticket_id = alert_data.get('id', 'N/A')
            assigned_str = alert_data.get('assigned_to', 'N/A')
        
        messages = [
            "📌 A ticket assigned to you has been updated.",
            f"🔹 Ticket ID: {ticket_id}",
            f"🔹 Assigned: {assigned_str}",
            "",
            "Regards,",
            "IT SUPPORT TEAM"
        ]
        return "\n".join(messages), assigned_str
    except Exception as e:
        logger.error(f"Ticket format error: {e}")
        return f"⚠️ Ticket System Error", "N/A"

# ============================================================================
# ROUTES
# ============================================================================

@app.route('/webhook/monitoring', methods=['POST'])
def webhook_monitoring():
    data = request.get_json(force=True, silent=True)
    if not data: return jsonify({'status': 'error'}), 400
    
    logger.info(f"📊 Received Alert")
    send_to_signal_group(GROUPS['grafana'], format_grafana_alert(data))
    return jsonify({'status': 'successful'}), 200

@app.route('/webhook/helpdesk', methods=['POST'])
def webhook_helpdesk():
    data = request.get_json(force=True, silent=True) or request.form.to_dict()
    logger.info(f"📥 Received Ticket Webhook")
    
    message, assigned_str = format_ticket_alert(data)
    
    # Logic to send individual notification to technicians
    tech_names = [name.strip() for name in assigned_str.replace(",", " ").split() if name.strip()]
    for name in tech_names:
        phone = get_technician_number(name)
        if phone:
            send_to_signal_group(phone, message)
            
    return jsonify({"status": "processed"}), 200

# ============================================================================
# DASHBOARD API
# ============================================================================

@app.route('/api/stats', methods=['GET'])
@login_required
def api_stats():
    return jsonify({
        'status': 'online',
        'metrics': {
            'throttle_active': len(ALERT_CACHE),
            'last_update': datetime.now().isoformat()
        }
    }), 200

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'}), 200

if __name__ == '__main__':
    load_config()
    load_cache()
    app.run(host=WEBHOOK_HOST, port=WEBHOOK_PORT)

