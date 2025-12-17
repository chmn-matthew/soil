from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_cors import CORS
from datetime import datetime, timedelta
import hashlib
import requests
import sqlite3
import json

app = Flask(__name__)
CORS(app)
app.secret_key = 'soilsense-local-secret-key-2025'

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_COOKIE_NAME'] = 'soilsense_local'

REGISTRATION_TOKEN = "12345678"

# Simple admin login credentials (independent from users table)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"  # change this if you want a different password

# ESP32 configuration
esp32_config = {
    "ip": None,
    "connected": False,
    "last_check": None
}
def adapt_datetime(dt):
    """Convert datetime to ISO format string for SQLite"""
    return dt.isoformat()

def convert_datetime(s):
    """Convert ISO format string back to datetime"""
    return datetime.fromisoformat(s.decode())

# Register adapters (add this before init_db())
sqlite3.register_adapter(datetime, adapt_datetime)
sqlite3.register_converter("timestamp", convert_datetime)


# ========== Database Setup ==========
def init_db():
    conn = sqlite3.connect('soilsense_local.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'farmer',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Add role column if it doesn't exist (migration for existing databases)
    try:
        c.execute('ALTER TABLE users ADD COLUMN role TEXT DEFAULT "farmer"')
        conn.commit()
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Ensure all existing users have a role set (update any NULL values)
    try:
        c.execute('UPDATE users SET role = "farmer" WHERE role IS NULL')
        conn.commit()
    except sqlite3.OperationalError:
        pass  # Role column might not exist (shouldn't happen, but safe to ignore)
    
    # Sensor history table
    c.execute('''CREATE TABLE IF NOT EXISTS sensor_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        soil_percent TEXT,
        soil_status TEXT,
        pump_status TEXT,
        mode TEXT,
        temperature REAL,
        humidity REAL,
        battery_voltage REAL,
        battery_percent REAL,
        current_consumed REAL,
        power_data TEXT,
        recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    
    # Pump events table
    c.execute('''CREATE TABLE IF NOT EXISTS pump_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        event_type TEXT,
        mode TEXT,
        triggered_by TEXT,
        soil_moisture REAL,
        recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    
    # Notifications table
    c.execute('''CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        type TEXT,
        title TEXT,
        message TEXT,
        is_read INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    
    # Inventory table (super admin)
    # Note: older databases may still have a 'sku' column; it is no longer used.
    c.execute('''CREATE TABLE IF NOT EXISTS inventory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        price REAL DEFAULT 0,
        stock INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Sales table (records items sold to users)
    c.execute('''CREATE TABLE IF NOT EXISTS sales (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        inventory_id INTEGER,
        quantity INTEGER DEFAULT 1,
        price_each REAL DEFAULT 0,
        total_amount REAL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (inventory_id) REFERENCES inventory(id)
    )''')
    
    # Seed inventory with hardware and SIM costing if not already present
    seed_items = [
        ("ESP32 Microcontroller", 360.0, 0),
        ("Soil Moisture Sensor", 70.0, 0),
        ("DHT11 Temp & Humidity Sensor", 70.0, 0),
        ("GSM Module (SIM800L)", 370.0, 0),
        ("INA219 Power Monitoring Sensor", 70.0, 0),
        ("Relay Module (5V Single Channel)", 125.0, 0),
        ("Water Pump (12V)", 260.0, 0),
        ("Sprinkler Head", 210.0, 0),
        ("Wires & Connectors", 200.0, 0),
        ("Plywood Weatherproof Enclosure", 500.0, 0),
        ("Solar Panel (220W)", 2200.0, 0),
        ("Solar Charge Controller", 450.0, 0),
        ("12V Rechargeable Battery", 900.0, 0),
        ("SIM - Globe (GoUNLI180)", 180.0, 0),
        ("SIM - TM (ALLTEXT100)", 100.0, 0),
        ("SIM - Smart (UnliTEXT150)", 150.0, 0),
        ("SIM - TNT (Unli Text 100)", 100.0, 0),
        ("SIM - DITO (Level-Up 199)", 199.0, 0),
        ("SIM - GOMO (Unli Text 30 Days)", 499.0, 0),
    ]
    for name, price, stock in seed_items:
        existing = c.execute("SELECT id FROM inventory WHERE name = ?", (name,)).fetchone()
        if not existing:
            c.execute(
                "INSERT INTO inventory (name, price, stock) VALUES (?, ?, ?)",
                (name, price, stock),
            )
    
    # ESP32 config table
    c.execute('''CREATE TABLE IF NOT EXISTS esp32_config (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        ip_address TEXT,
        last_connected TIMESTAMP
    )''')
    
    c.execute('INSERT OR IGNORE INTO esp32_config (id) VALUES (1)')
    
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect('soilsense_local.db', detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_notification(user_id, notif_type, title, message):
    """Create a notification for user"""
    conn = get_db()
    conn.execute('''INSERT INTO notifications (user_id, type, title, message)
                   VALUES (?, ?, ?, ?)''', (user_id, notif_type, title, message))
    conn.commit()
    conn.close()

def save_sensor_data(user_id, data):
    """Save sensor data to history"""
    conn = get_db()
    
    # Save to sensor history
    soil_percent = json.dumps(data.get('soil_percent', []))
    power_data = json.dumps(data.get('power', {}))
    
    conn.execute('''INSERT INTO sensor_history 
        (user_id, soil_percent, soil_status, pump_status, mode, 
         temperature, humidity, battery_voltage, battery_percent, 
         current_consumed, power_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (user_id, soil_percent, data.get('soil_status'), data.get('pump_status'),
         data.get('mode'), data.get('temperature'), data.get('humidity'),
         data.get('battery_voltage'), data.get('battery_percent'),
         data.get('current_consumed'), power_data))
    
    conn.commit()
    conn.close()

def save_pump_event(user_id, event_type, mode, soil_moisture):
    """Save pump event (ON/OFF)"""
    conn = get_db()
    
    triggered_by = "manual" if mode == "MANUAL" else "auto"
    
    conn.execute('''INSERT INTO pump_events 
        (user_id, event_type, mode, triggered_by, soil_moisture)
        VALUES (?, ?, ?, ?, ?)''',
        (user_id, event_type, mode, triggered_by, soil_moisture))
    
    conn.commit()
    conn.close()
    
    # Create notification for pump events
    if event_type == "PUMP_ON":
        create_notification(user_id, "pump", "Pump Activated", 
                          f"Pump turned ON ({triggered_by} mode)")
    elif event_type == "PUMP_OFF":
        create_notification(user_id, "pump", "Pump Deactivated", 
                          f"Pump turned OFF ({triggered_by} mode)")

# Track last pump status to detect changes
last_pump_status = None

def get_esp32_data():
    """Fetch data from ESP32"""
    global last_pump_status
    
    if not esp32_config["ip"]:
        return {"error": "ESP32 IP not configured", "online": False}
    
    try:
        response = requests.get(f"http://{esp32_config['ip']}/api/data", timeout=5)
        if response.status_code == 200:
            data = response.json()
            data['online'] = True
            esp32_config['connected'] = True
            esp32_config['last_check'] = datetime.now()
            
            # Save ESP32 IP to database - FIX: Use ISO format
            conn = get_db()
            now_iso = datetime.now().isoformat()
            conn.execute('UPDATE esp32_config SET ip_address = ?, last_connected = ? WHERE id = 1',
                        (esp32_config['ip'], now_iso))
            conn.commit()
            conn.close()
            
            # Check for pump status change
            current_pump_status = data.get('pump_status')
            if last_pump_status is not None and last_pump_status != current_pump_status:
                if 'username' in session:
                    user_id = get_user_id(session['username'])
                    if user_id:
                        soil_avg = sum(data.get('soil_percent', [0,0,0,0])) / 4
                        event_type = "PUMP_ON" if current_pump_status == "ON" else "PUMP_OFF"
                        save_pump_event(user_id, event_type, data.get('mode', 'AUTO'), soil_avg)
            
            last_pump_status = current_pump_status
            
            return data
        else:
            esp32_config['connected'] = False
            return {"error": "ESP32 responded with error", "online": False}
    except Exception as e:
        esp32_config['connected'] = False
        return {"error": str(e), "online": False}

def send_esp32_command(endpoint, data):
    """Send command to ESP32"""
    if not esp32_config["ip"]:
        return {"success": False, "error": "ESP32 IP not configured"}
    
    try:
        response = requests.post(
            f"http://{esp32_config['ip']}/api/{endpoint}",
            json=data,
            timeout=5
        )
        if response.status_code == 200:
            return response.json()
        else:
            return {"success": False, "error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def get_user_id(username):
    """Get user ID from username"""
    conn = get_db()
    user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user['id'] if user else None

def get_user_role(username):
    """Get user role from username. Returns 'farmer' by default."""
    conn = get_db()
    try:
        user = conn.execute('SELECT role FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if not user:
            return 'farmer'
        # sqlite3.Row objects use bracket notation, not .get()
        # If role is None or empty, default to 'farmer'
        role = user['role'] if user['role'] else 'farmer'
        return role
    except (sqlite3.OperationalError, KeyError, TypeError):
        # Column might not exist yet or other issues (shouldn't happen after migration, but safe)
        try:
            conn.close()
        except:
            pass
        return 'farmer'

def is_super_admin(username):
    """Check if user is super admin"""
    return get_user_role(username) == 'super_admin'

# ========== Auth Routes ==========
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and user['password'] == hash_password(password):
            session['username'] = username
            session.permanent = True
            return redirect(url_for('dashboard'))
        
        return render_template('login.html', error='Invalid username or password')
    return render_template('login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    """
    Separate login for admin dashboard.
    Uses simple hardcoded credentials (ADMIN_USERNAME / ADMIN_PASSWORD).
    """
    # If already logged in as admin, go straight to admin page
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            error = 'Invalid admin username or password'

    return render_template('admin_login.html', error=error)

@app.route('/admin_logout')
def admin_logout():
    """Log out only from the admin dashboard (keep user session separate)."""
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        token = request.form.get('token')
        
        if token != REGISTRATION_TOKEN:
            return render_template('register.html', error='Invalid registration token')
        
        if password != confirm_password:
            return render_template('register.html', error='Passwords do not match')
        
        if len(password) < 6:
            return render_template('register.html', error='Password must be at least 6 characters')
        
        conn = get_db()
        
        existing = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing:
            conn.close()
            return render_template('register.html', error='Username already exists')
        
        # Default role is 'farmer', can be set to 'super_admin' manually in DB
        conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                    (username, hash_password(password), 'farmer'))
        conn.commit()
        conn.close()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ========== Dashboard Route ==========
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Load ESP32 IP from database
    if not esp32_config['ip']:
        conn = get_db()
        config = conn.execute('SELECT ip_address FROM esp32_config WHERE id = 1').fetchone()
        conn.close()
        if config and config['ip_address']:
            esp32_config['ip'] = config['ip_address']
    
    # Get current month name
    current_month = datetime.now().strftime('%B %Y')
    
    return render_template('dashboard.html', 
                         username=session['username'],
                         esp32_ip=esp32_config['ip'],
                         current_month=current_month)

# ========== Settings Route ==========
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        esp32_ip = request.form.get('esp32_ip')
        esp32_config['ip'] = esp32_ip
        
        # Save to database
        conn = get_db()
        conn.execute('UPDATE esp32_config SET ip_address = ? WHERE id = 1', (esp32_ip,))
        conn.commit()
        conn.close()
        
        return render_template('settings.html', 
                             username=session['username'],
                             esp32_ip=esp32_config['ip'],
                             success='ESP32 IP address saved!')
    
    return render_template('settings.html', 
                         username=session['username'],
                         esp32_ip=esp32_config['ip'])

# ========== History Route ==========
@app.route('/history')
def history():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    return render_template('history.html', username=session['username'])

# ========== API Routes ==========
@app.route('/api/data')
def api_data():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = get_esp32_data()
    
    # Save data to history every fetch
    if data.get('online'):
        user_id = get_user_id(session['username'])
        if user_id:
            save_sensor_data(user_id, data)
    
    return jsonify(data)

@app.route('/api/mode/<mode>')
def set_mode(mode):
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    result = send_esp32_command('mode', {'mode': mode.upper()})
    
    if result.get('success'):
        user_id = get_user_id(session['username'])
        if user_id:
            create_notification(user_id, "mode", "Mode Changed", 
                              f"System mode changed to {mode.upper()}")
    
    return jsonify(result)

@app.route('/api/pump/<state>')
def set_pump(state):
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    result = send_esp32_command('pump', {'state': state.upper()})
    return jsonify(result)

@app.route('/api/esp32/status')
def esp32_status():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    return jsonify({
        "ip": esp32_config['ip'],
        "connected": esp32_config['connected'],
        "last_check": esp32_config['last_check'].isoformat() if esp32_config['last_check'] else None
    })

# ========== History API ==========
@app.route('/api/history/sensor')
def get_sensor_history():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = get_user_id(session['username'])
    limit = request.args.get('limit', 50, type=int)
    
    conn = get_db()
    history = conn.execute('''SELECT * FROM sensor_history 
                             WHERE user_id = ? 
                             ORDER BY recorded_at DESC 
                             LIMIT ?''', (user_id, limit)).fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in history])

@app.route('/api/history/pump')
def get_pump_history():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = get_user_id(session['username'])
    limit = request.args.get('limit', 100, type=int)
    
    conn = get_db()
    events = conn.execute('''SELECT * FROM pump_events 
                            WHERE user_id = ? 
                            ORDER BY recorded_at DESC 
                            LIMIT ?''', (user_id, limit)).fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in events])

@app.route('/api/history/stats')
def get_history_stats():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = get_user_id(session['username'])
    
    conn = get_db()
    
    # Get stats for last 7 days
    seven_days_ago = datetime.now() - timedelta(days=7)
    
    pump_stats = conn.execute('''SELECT 
        COUNT(CASE WHEN event_type = 'PUMP_ON' THEN 1 END) as on_count,
        COUNT(CASE WHEN event_type = 'PUMP_OFF' THEN 1 END) as off_count,
        COUNT(CASE WHEN triggered_by = 'manual' THEN 1 END) as manual_count,
        COUNT(CASE WHEN triggered_by = 'auto' THEN 1 END) as auto_count
        FROM pump_events 
        WHERE user_id = ? AND recorded_at >= ?''',
        (user_id, seven_days_ago)).fetchone()
    
    conn.close()
    
    return jsonify({
        "pump": {
            "total_on_events": pump_stats['on_count'],
            "total_off_events": pump_stats['off_count'],
            "manual_events": pump_stats['manual_count'],
            "auto_events": pump_stats['auto_count']
        }
    })

# ========== Notifications API ==========
@app.route('/api/notifications')
def get_notifications():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = get_user_id(session['username'])
    limit = request.args.get('limit', 20, type=int)
    
    conn = get_db()
    notifications = conn.execute('''SELECT * FROM notifications 
                                   WHERE user_id = ? 
                                   ORDER BY created_at DESC 
                                   LIMIT ?''', (user_id, limit)).fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in notifications])

@app.route('/api/notifications/unread')
def get_unread_count():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = get_user_id(session['username'])
    
    conn = get_db()
    count = conn.execute('''SELECT COUNT(*) as count FROM notifications 
                           WHERE user_id = ? AND is_read = 0''', (user_id,)).fetchone()
    conn.close()
    
    return jsonify({"count": count['count']})

@app.route('/api/notifications/<int:notif_id>/read', methods=['POST'])
def mark_notification_read(notif_id):
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = get_user_id(session['username'])
    
    conn = get_db()
    conn.execute('''UPDATE notifications SET is_read = 1 
                   WHERE id = ? AND user_id = ?''', (notif_id, user_id))
    conn.commit()
    conn.close()
    
    return jsonify({"success": True})

@app.route('/api/notifications/read-all', methods=['POST'])
def mark_all_read():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = get_user_id(session['username'])
    
    conn = get_db()
    conn.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    return jsonify({"success": True})

# ========== Admin Routes (protected by admin_login) ==========
@app.route('/admin')
def admin_dashboard():
    """Admin web dashboard - requires admin_login."""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    return render_template('admin_dashboard.html')

@app.route('/api/admin/farmers')
def get_all_farmers():
    """Get all farmers for admin dashboard (requires admin_login)."""
    if not session.get('admin_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    farmers = conn.execute('SELECT id, username, role, created_at FROM users ORDER BY created_at DESC').fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in farmers])

@app.route('/api/admin/farmers/<int:farmer_id>/stats')
def get_farmer_stats(farmer_id):
    """Get statistics for a specific farmer (requires admin_login)."""
    if not session.get('admin_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    
    # Verify farmer exists
    farmer = conn.execute('SELECT username FROM users WHERE id = ?', (farmer_id,)).fetchone()
    if not farmer:
        conn.close()
        return jsonify({"error": "Farmer not found"}), 404
    
    # Get stats for last 7 days
    seven_days_ago = datetime.now() - timedelta(days=7)
    thirty_days_ago = datetime.now() - timedelta(days=30)
    
    # Pump events stats
    pump_stats = conn.execute('''SELECT 
        COUNT(CASE WHEN event_type = 'PUMP_ON' THEN 1 END) as on_count,
        COUNT(CASE WHEN event_type = 'PUMP_OFF' THEN 1 END) as off_count,
        COUNT(CASE WHEN triggered_by = 'manual' THEN 1 END) as manual_count,
        COUNT(CASE WHEN triggered_by = 'auto' THEN 1 END) as auto_count
        FROM pump_events 
        WHERE user_id = ? AND recorded_at >= ?''',
        (farmer_id, seven_days_ago)).fetchone()
    
    # Total sensor readings
    sensor_count = conn.execute('''SELECT COUNT(*) as count FROM sensor_history 
                                  WHERE user_id = ? AND recorded_at >= ?''',
                                  (farmer_id, seven_days_ago)).fetchone()
    
    # Average soil moisture (last 7 days)
    sensor_data = conn.execute('''SELECT soil_percent FROM sensor_history 
                                 WHERE user_id = ? AND recorded_at >= ?
                                 ORDER BY recorded_at DESC LIMIT 100''',
                                 (farmer_id, seven_days_ago)).fetchall()
    
    avg_soil = 0
    if sensor_data:
        soil_values = []
        for row in sensor_data:
            try:
                soil_array = json.loads(row['soil_percent'])
                if isinstance(soil_array, list) and len(soil_array) > 0:
                    soil_values.extend(soil_array)
            except (json.JSONDecodeError, TypeError, KeyError):
                pass
        if soil_values:
            avg_soil = sum(soil_values) / len(soil_values)
    
    # Average temperature and humidity
    env_stats = conn.execute('''SELECT 
        AVG(temperature) as avg_temp,
        AVG(humidity) as avg_humidity
        FROM sensor_history 
        WHERE user_id = ? AND recorded_at >= ?
        AND temperature IS NOT NULL AND humidity IS NOT NULL''',
        (farmer_id, seven_days_ago)).fetchone()
    
    # Last activity
    last_sensor = conn.execute('''SELECT recorded_at FROM sensor_history 
                                 WHERE user_id = ? 
                                 ORDER BY recorded_at DESC LIMIT 1''',
                                 (farmer_id,)).fetchone()
    
    last_pump = conn.execute('''SELECT recorded_at FROM pump_events 
                               WHERE user_id = ? 
                               ORDER BY recorded_at DESC LIMIT 1''',
                               (farmer_id,)).fetchone()
    
    conn.close()
    
    # Safely convert datetime to ISO format string
    def safe_isoformat(dt):
        if dt is None:
            return None
        if isinstance(dt, datetime):
            return dt.isoformat()
        if isinstance(dt, str):
            return dt
        return str(dt)
    
    # Safely get datetime from Row objects (sqlite3.Row uses bracket notation, not .get())
    last_sensor_dt = None
    if last_sensor:
        try:
            last_sensor_dt = last_sensor['recorded_at']
        except (KeyError, TypeError):
            pass
    
    last_pump_dt = None
    if last_pump:
        try:
            last_pump_dt = last_pump['recorded_at']
        except (KeyError, TypeError):
            pass
    
    return jsonify({
        "farmer_id": farmer_id,
        "farmer_username": farmer['username'],
        "pump": {
            "total_on_events": pump_stats['on_count'],
            "total_off_events": pump_stats['off_count'],
            "manual_events": pump_stats['manual_count'],
            "auto_events": pump_stats['auto_count']
        },
        "sensor_readings_count": sensor_count['count'],
        "average_soil_moisture": round(avg_soil, 2) if avg_soil > 0 else None,
        "average_temperature": round(env_stats['avg_temp'], 2) if env_stats['avg_temp'] else None,
        "average_humidity": round(env_stats['avg_humidity'], 2) if env_stats['avg_humidity'] else None,
        "last_sensor_activity": safe_isoformat(last_sensor_dt),
        "last_pump_activity": safe_isoformat(last_pump_dt)
    })

@app.route('/api/admin/farmers/<int:farmer_id>/sensor-history')
def get_farmer_sensor_history(farmer_id):
    """Get sensor history for a specific farmer (requires admin_login)."""
    if not session.get('admin_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    limit = request.args.get('limit', 100, type=int)
    
    conn = get_db()
    history = conn.execute('''SELECT * FROM sensor_history 
                             WHERE user_id = ? 
                             ORDER BY recorded_at DESC 
                             LIMIT ?''', (farmer_id, limit)).fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in history])

@app.route('/api/admin/farmers/<int:farmer_id>/pump-history')
def get_farmer_pump_history(farmer_id):
    """Get pump history for a specific farmer (requires admin_login)."""
    if not session.get('admin_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    limit = request.args.get('limit', 100, type=int)
    
    conn = get_db()
    events = conn.execute('''SELECT * FROM pump_events 
                            WHERE user_id = ? 
                            ORDER BY recorded_at DESC 
                            LIMIT ?''', (farmer_id, limit)).fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in events])

@app.route('/api/admin/overview')
def get_admin_overview():
    """Get overview statistics for all farmers (requires admin_login)."""
    if not session.get('admin_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    
    # Total farmers
    total_farmers = conn.execute('SELECT COUNT(*) as count FROM users WHERE role = "farmer"').fetchone()
    
    # Total sensor readings (last 7 days)
    seven_days_ago = datetime.now() - timedelta(days=7)
    total_readings = conn.execute('''SELECT COUNT(*) as count FROM sensor_history 
                                    WHERE recorded_at >= ?''', (seven_days_ago,)).fetchone()
    
    # Total pump events (last 7 days)
    total_pump_events = conn.execute('''SELECT COUNT(*) as count FROM pump_events 
                                       WHERE recorded_at >= ?''', (seven_days_ago,)).fetchone()
    
    # Active farmers (with activity in last 7 days)
    active_farmers = conn.execute('''SELECT COUNT(DISTINCT user_id) as count FROM sensor_history 
                                    WHERE recorded_at >= ?''', (seven_days_ago,)).fetchone()
    
    # Sales and inventory aggregates
    sales_totals = conn.execute('''SELECT 
            COALESCE(SUM(quantity), 0) as total_units_sold,
            COALESCE(SUM(total_amount), 0) as total_revenue
        FROM sales''').fetchone()
    
    inventory_totals = conn.execute('''SELECT 
            COUNT(*) as total_items,
            COALESCE(SUM(stock), 0) as total_stock
        FROM inventory''').fetchone()
    
    conn.close()
    
    return jsonify({
        "total_farmers": total_farmers['count'],
        "active_farmers": active_farmers['count'],
        "total_sensor_readings": total_readings['count'],
        "total_pump_events": total_pump_events['count'],
        "inventory": {
            "total_items": inventory_totals['total_items'],
            "total_stock": inventory_totals['total_stock']
        },
        "sales": {
            "total_units_sold": sales_totals['total_units_sold'],
            "total_revenue": round(sales_totals['total_revenue'], 2)
        }
    })

@app.route('/api/admin/inventory')
def admin_inventory():
    """List inventory with sold counts (requires admin_login)."""
    if not session.get('admin_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    
    conn = get_db()
    items = conn.execute('''
        SELECT 
            i.id,
            i.name,
            i.price,
            i.stock,
            i.created_at,
            COALESCE(SUM(s.quantity), 0) as units_sold,
            COALESCE(SUM(s.total_amount), 0) as revenue
        FROM inventory i
        LEFT JOIN sales s ON s.inventory_id = i.id
        GROUP BY i.id
        ORDER BY i.created_at DESC
    ''').fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in items])

@app.route('/api/admin/sales/by-user')
def admin_sales_by_user():
    """Sales summary by user (requires admin_login)."""
    if not session.get('admin_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    
    conn = get_db()
    rows = conn.execute('''
        SELECT 
            u.id as user_id,
            u.username,
            COALESCE(SUM(s.quantity), 0) as total_units,
            COALESCE(SUM(s.total_amount), 0) as total_revenue
        FROM users u
        LEFT JOIN sales s ON s.user_id = u.id
        WHERE u.role = 'farmer'
        GROUP BY u.id
        ORDER BY total_revenue DESC, total_units DESC
    ''').fetchall()
    conn.close()
    
    return jsonify([dict(r) for r in rows])

if __name__ == '__main__':
    print("\n" + "="*60)
    print("  SoilSense Local Server")
    print("="*60)
    print("  1. Open http://localhost:5000")
    print("  2. Register with token: 12345678")
    print("  3. Go to Settings and enter your ESP32 IP address")
    print("  Database: soilsense_local.db")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=True)