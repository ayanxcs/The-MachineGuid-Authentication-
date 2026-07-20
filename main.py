import os
import json
import uuid
import shutil
import hashlib
import threading
import traceback
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, session, render_template_string, redirect, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix

# Server configuration & admin credentials
app = Flask(__name__, static_folder='.', template_folder='.')
app.secret_key = os.environ.get('SECRET_KEY', 'default-session-secret-key-change-in-production')
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

secure_cookie = os.environ.get('SECURE_COOKIE', 'false').lower() == 'true'
app.config.update(
    SESSION_COOKIE_SECURE=secure_cookie,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24),
    SESSION_TYPE='filesystem'
)

ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
DATA_DIR = Path("database")
BACKUP_DIR = Path("backups")

DATA_DIR.mkdir(exist_ok=True)
BACKUP_DIR.mkdir(exist_ok=True)

USERS_FILE = DATA_DIR / "users.json"
HWID_FILE = DATA_DIR / "hwid.json"
LOGS_FILE = DATA_DIR / "logs.json"

file_lock = threading.Lock()

def init_database():
    default_files = {
        USERS_FILE: {"users": []},
        HWID_FILE: {"hwids": []},
        LOGS_FILE: {"logs": []}
    }
    for file_path, default_data in default_files.items():
        if not file_path.exists():
            try:
                with open(file_path, 'w') as f:
                    json.dump(default_data, f, indent=2)
            except Exception as e:
                print(f"Error initializing {file_path}: {e}")

def read_json(file_path):
    with file_lock:
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return {"users": [], "hwids": [], "logs": []}.get(file_path.stem, {})

def write_json(file_path, data):
    with file_lock:
        try:
            if file_path.exists():
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = BACKUP_DIR / f"{file_path.stem}_backup_{timestamp}.json"
                shutil.copy(file_path, backup_path)
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            print(f"Error writing {file_path}: {e}")
            return False

def add_log(event, username=None, hwid=None, details=None):
    try:
        logs_data = read_json(LOGS_FILE)
        log_entry = {
            "id": str(uuid.uuid4()),
            "event": event,
            "username": username,
            "hwid": hwid,
            "date": datetime.now().isoformat(),
            "details": details
        }
        logs_data["logs"].insert(0, log_entry)
        if len(logs_data["logs"]) > 1000:
            logs_data["logs"] = logs_data["logs"][:1000]
        write_json(LOGS_FILE, logs_data)
        
        queue_file = DATA_DIR / "log_queue.json"
        with file_lock:
            queue_data = {"queue": []}
            if queue_file.exists():
                try:
                    with open(queue_file, 'r') as f:
                        queue_data = json.load(f)
                except:
                    pass
            queue_data["queue"].append(log_entry)
            with open(queue_file, 'w') as f:
                json.dump(queue_data, f)
                
    except Exception as e:
        print(f"Error adding log: {e}")

def get_device_fingerprint():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()
    ua = request.headers.get('User-Agent', '')
    fingerprint = hashlib.sha256(f"{ip}:{ua}".encode()).hexdigest()[:32]
    return fingerprint, ip, ua

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('admin_logged_in') != True:
            return redirect('/')
        return f(*args, **kwargs)
    return decorated

def user_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_logged_in') and not session.get('admin_logged_in'):
            return redirect('/')
        return f(*args, **kwargs)
    return decorated

init_database()

# --- UI Templates (Login, User Dashboard, Admin Control) ---

# Login page UI
LOGIN_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DELETE HEX — Secure Access</title>
    <style>
        :root {
            --void: #050505;
            --carbon: #0a0a0a;
            --graphite: #141414;
            --steel: #1f1f1f;
            --mist: rgba(255, 255, 255, 0.04);
            --fog: rgba(255, 255, 255, 0.08);
            --ghost: rgba(255, 255, 255, 0.6);
            --pure: #ffffff;
            --accent: #3b3b3b;
            --error: #ff3333;
            --neon: #00ff88;
            --ease-out-expo: cubic-bezier(0.16, 1, 0.3, 1);
            --ease-in-out-sine: cubic-bezier(0.37, 0, 0.63, 1);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        html { font-size: 16px; -webkit-font-smoothing: antialiased; }
        body {
            font-family: 'SF Pro Display', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--void);
            color: var(--pure);
            min-height: 100vh;
            overflow: hidden;
            position: relative;
            line-height: 1.6;
        }
        .noise-overlay {
            position: fixed;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)' opacity='0.03'/%3E%3C/svg%3E");
            animation: noise 8s steps(10) infinite;
            pointer-events: none;
            z-index: 50;
            opacity: 0.4;
        }
        @keyframes noise {
            0%, 100% { transform: translate(0, 0); }
            10% { transform: translate(-5%, -10%); }
            20% { transform: translate(-15%, 5%); }
            30% { transform: translate(7%, -25%); }
            40% { transform: translate(-5%, 25%); }
            50% { transform: translate(-15%, 10%); }
            60% { transform: translate(15%, 0%); }
            70% { transform: translate(0%, 15%); }
            80% { transform: translate(3%, 35%); }
            90% { transform: translate(-10%, 10%); }
        }
        .glow-orb {
            position: fixed;
            width: 600px;
            height: 600px;
            background: radial-gradient(circle, rgba(255,255,255,0.03) 0%, transparent 70%);
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            pointer-events: none;
            z-index: 1;
            animation: breathe 6s var(--ease-in-out-sine) infinite;
        }
        @keyframes breathe {
            0%, 100% { transform: translate(-50%, -50%) scale(1); opacity: 0.5; }
            50% { transform: translate(-50%, -50%) scale(1.2); opacity: 0.8; }
        }
        .grid-background {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 0;
            pointer-events: none;
            opacity: 0;
            animation: fadeIn 2s var(--ease-out-expo) 0.5s forwards;
        }
        .grid-line {
            position: absolute;
            background: linear-gradient(to bottom, transparent, rgba(255,255,255,0.03), transparent);
            width: 1px;
            height: 100%;
            top: 0;
            transform: translateY(-100%);
            animation: dropIn 1.5s var(--ease-out-expo) forwards;
        }
        .grid-line:nth-child(1) { left: 10%; animation-delay: 0.2s; }
        .grid-line:nth-child(2) { left: 30%; animation-delay: 0.4s; }
        .grid-line:nth-child(3) { left: 50%; animation-delay: 0.6s; height: 60%; top: 20%; }
        .grid-line:nth-child(4) { left: 70%; animation-delay: 0.8s; }
        .grid-line:nth-child(5) { left: 90%; animation-delay: 1s; }
        @keyframes dropIn { to { transform: translateY(0); } }
        .top-bar {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            padding: 2rem 3rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            z-index: 100;
            mix-blend-mode: difference;
        }
        .brand-lockup {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            opacity: 0;
            transform: translateY(-20px);
            animation: slideDown 0.8s var(--ease-out-expo) 0.2s forwards;
        }
        .brand-text {
            font-size: 0.875rem;
            font-weight: 700;
            letter-spacing: 0.2em;
            text-transform: uppercase;
            color: var(--pure);
        }
        .status-indicator {
            width: 6px;
            height: 6px;
            background: var(--neon);
            border-radius: 50%;
            box-shadow: 0 0 10px var(--neon);
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.5; transform: scale(0.8); }
        }
        @keyframes slideDown {
            to { opacity: 1; transform: translateY(0); }
        }
        .header-nav {
            display: flex;
            align-items: center;
            gap: 2rem;
            opacity: 0;
            animation: fadeIn 0.8s var(--ease-out-expo) 0.4s forwards;
        }
        @keyframes fadeIn { to { opacity: 1; } }
        .nav-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--ghost);
            text-decoration: none;
            font-size: 0.8125rem;
            font-weight: 500;
            letter-spacing: 0.05em;
            transition: all 0.3s var(--ease-out-expo);
            position: relative;
            overflow: hidden;
        }
        .nav-text { position: relative; transform: translateY(0); transition: transform 0.3s var(--ease-out-expo); }
        .nav-arrow { opacity: 0; transform: translateX(-10px); transition: all 0.3s var(--ease-out-expo); }
        .nav-item:hover { color: var(--pure); }
        .nav-item:hover .nav-text { transform: translateY(-1px); }
        .nav-item:hover .nav-arrow { opacity: 1; transform: translateX(0); }
        .logo-container { width: 32px; height: 32px; position: relative; overflow: hidden; }
        .logo-mark {
            width: 100%;
            height: 100%;
            object-fit: contain;
            filter: grayscale(100%) brightness(2);
            opacity: 0.8;
            transition: all 0.4s var(--ease-out-expo);
            transform: scale(0.95);
        }
        .logo-container:hover .logo-mark {
            opacity: 1;
            transform: scale(1);
            filter: grayscale(100%) brightness(2.5) drop-shadow(0 0 10px rgba(255,255,255,0.3));
        }
        .login-stage {
            position: relative;
            z-index: 10;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
        }
        .login-container { width: 100%; max-width: 420px; position: relative; }
        .login-header {
            margin-bottom: 3rem;
            text-align: center;
            opacity: 0;
            transform: translateY(30px);
            animation: slideUp 0.8s var(--ease-out-expo) 0.6s forwards;
        }
        @keyframes slideUp {
            to { opacity: 1; transform: translateY(0); }
        }
        .title-glitch {
            font-size: 1.75rem;
            font-weight: 600;
            letter-spacing: -0.02em;
            margin-bottom: 0.5rem;
            position: relative;
            display: inline-block;
        }
        .subtitle {
            font-size: 0.75rem;
            color: var(--ghost);
            letter-spacing: 0.15em;
            text-transform: uppercase;
            font-weight: 500;
        }
        .auth-form { position: relative; }
        .input-matrix {
            margin-bottom: 2rem;
            opacity: 0;
            transform: translateY(20px);
            animation: slideUp 0.8s var(--ease-out-expo) 0.8s forwards;
        }
        .field-group { position: relative; height: 56px; }
        .field-group input {
            width: 100%;
            height: 100%;
            background: transparent;
            border: none;
            outline: none;
            color: var(--pure);
            font-size: 1rem;
            font-family: inherit;
            padding: 1.25rem 1rem 0.5rem;
            position: relative;
            z-index: 2;
            letter-spacing: 0.02em;
        }
        .field-group label {
            position: absolute;
            left: 1rem;
            top: 50%;
            transform: translateY(-50%);
            color: var(--ghost);
            font-size: 0.9375rem;
            pointer-events: none;
            transition: all 0.3s var(--ease-out-expo);
            z-index: 1;
        }
        .field-border {
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: var(--mist);
            transition: all 0.4s var(--ease-out-expo);
        }
        .field-border::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 50%;
            width: 0;
            height: 1px;
            background: var(--pure);
            transition: all 0.4s var(--ease-out-expo);
            transform: translateX(-50%);
        }
        .field-glow {
            position: absolute;
            bottom: -1px;
            left: 0;
            right: 0;
            height: 1px;
            background: var(--pure);
            opacity: 0;
            filter: blur(4px);
            transition: opacity 0.3s ease;
        }
        .field-group input:focus ~ .field-border::after { width: 100%; }
        .field-group input:focus ~ .field-glow { opacity: 0.5; }
        .field-group input:focus ~ label,
        .field-group input:not(:placeholder-shown) ~ label {
            top: 0.75rem;
            transform: translateY(0);
            font-size: 0.6875rem;
            color: var(--ghost);
            letter-spacing: 0.1em;
            text-transform: uppercase;
        }
        .field-group input:focus ~ label { color: var(--pure); }
        .error-msg {
            color: var(--error);
            font-size: 0.8125rem;
            text-align: center;
            margin-bottom: 1rem;
            min-height: 1.25rem;
            opacity: 0;
            animation: fadeIn 0.3s forwards;
        }
        .access-btn {
            width: 100%;
            height: 52px;
            background: var(--pure);
            color: var(--void);
            border: none;
            font-family: inherit;
            font-size: 0.8125rem;
            font-weight: 600;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            cursor: pointer;
            position: relative;
            overflow: hidden;
            opacity: 0;
            transform: translateY(20px);
            animation: slideUp 0.8s var(--ease-out-expo) 1s forwards;
            transition: transform 0.2s var(--ease-out-expo);
        }
        .btn-text {
            position: relative;
            z-index: 2;
            display: inline-block;
            transition: transform 0.3s var(--ease-out-expo);
        }
        .btn-shine {
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent);
            transition: left 0.6s var(--ease-out-expo);
            z-index: 1;
        }
        .access-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 40px -10px rgba(255,255,255,0.2);
        }
        .access-btn:hover .btn-shine { left: 100%; }
        .access-btn:hover .btn-text { transform: scale(0.98); }
        .access-btn:active { transform: translateY(0) scale(0.98); }
        .security-footer {
            margin-top: 3rem;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            font-size: 0.6875rem;
            color: var(--ghost);
            letter-spacing: 0.1em;
            text-transform: uppercase;
            opacity: 0;
            animation: fadeIn 0.8s var(--ease-out-expo) 1.2s forwards;
        }
        .lock-icon { color: var(--neon); font-size: 0.875rem; animation: lockPulse 3s infinite; }
        @keyframes lockPulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        ::selection { background: rgba(255,255,255,0.15); color: var(--pure); }
    </style>
</head>
<body>
    <div class="noise-overlay"></div>
    <div class="glow-orb"></div>
    
    <header class="top-bar">
        <div class="brand-lockup">
            <span class="brand-text">DELETE HEX</span>
            <span class="status-indicator"></span>
        </div>
        <nav class="header-nav">
            <a href="https://discord.gg" class="nav-item" target="_blank">
                <span class="nav-text">Contact</span>
                <span class="nav-arrow">→</span>
            </a>
            <div class="logo-container">
                <img src="/static/logo1.png" alt="" class="logo-mark" onerror="this.style.display='none'">
            </div>
        </nav>
    </header>

    <main class="login-stage">
        <div class="login-container">
            <div class="login-header">
                <h1 class="title-glitch">Secure Access</h1>
                <p class="subtitle">Authentication Required</p>
            </div>
            
            <form id="loginForm" class="auth-form" onsubmit="return handleLogin(event)">
                <div class="input-matrix">
                    <div class="field-group">
                        <input type="text" id="username" required placeholder=" " autocomplete="off" spellcheck="false">
                        <label for="username">Username</label>
                        <div class="field-border"></div>
                        <div class="field-glow"></div>
                    </div>
                </div>
                
                <div class="error-msg" id="errorMsg"></div>
                
                <button type="submit" class="access-btn">
                    <span class="btn-text">Initialize Session</span>
                    <span class="btn-shine"></span>
                </button>
            </form>
            
            <div class="security-footer">
                <span class="lock-icon">◉</span>
                <span>End-to-end encrypted • Device Locked</span>
            </div>
        </div>
    </main>

    <div class="grid-background">
        <div class="grid-line"></div>
        <div class="grid-line"></div>
        <div class="grid-line"></div>
        <div class="grid-line"></div>
        <div class="grid-line"></div>
    </div>

    <script>
        async function handleLogin(e) {
            e.preventDefault();
            const username = document.getElementById('username').value.trim();
            const errorDiv = document.getElementById('errorMsg');
            
            if (!username) {
                errorDiv.textContent = 'Username required';
                errorDiv.style.opacity = '1';
                return false;
            }
            
            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username: username})
                });
                
                let data;
                try {
                    data = await response.json();
                } catch (parseError) {
                    throw new Error('Invalid server response');
                }
                
                if (data.status === 'ok') {
                    if (data.role === 'admin') {
                        window.location.href = '/admin';
                    } else {
                        window.location.href = '/dashboard';
                    }
                } else {
                    errorDiv.textContent = data.message || 'Authentication failed';
                    errorDiv.style.opacity = '1';
                }
            } catch (err) {
                errorDiv.textContent = 'Connection error: ' + err.message;
                errorDiv.style.opacity = '1';
                console.error('Login error:', err);
            }
            return false;
        }
    </script>
</body>
</html>'''

# User dashboard UI
USER_DASHBOARD_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DELETE HEX — User Dashboard</title>
    <style>
        :root {
            --void: #030303;
            --carbon: #080808;
            --graphite: #111111;
            --steel: #1a1a1a;
            --mist: rgba(255, 255, 255, 0.03);
            --fog: rgba(255, 255, 255, 0.06);
            --ghost: rgba(255, 255, 255, 0.5);
            --pure: #ffffff;
            --neon: #00ff88;
            --alert: #ff4757;
            --warn: #ffa502;
            --ease-out-expo: cubic-bezier(0.16, 1, 0.3, 1);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        html { font-size: 16px; -webkit-font-smoothing: antialiased; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--void);
            color: var(--pure);
            min-height: 100vh;
            line-height: 1.6;
        }
        .noise-overlay {
            position: fixed;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 400 400' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.8' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)'/%3E%3C/svg%3E");
            opacity: 0.02;
            pointer-events: none;
            z-index: 1000;
            animation: grain 8s steps(10) infinite;
        }
        @keyframes grain {
            0%, 100% { transform: translate(0, 0); }
            10% { transform: translate(-5%, -5%); }
            20% { transform: translate(-10%, 5%); }
            30% { transform: translate(5%, -10%); }
            40% { transform: translate(-5%, 15%); }
            50% { transform: translate(-10%, 5%); }
            60% { transform: translate(15%, 0); }
            70% { transform: translate(0, 10%); }
            80% { transform: translate(-15%, 0); }
            90% { transform: translate(10%, 5%); }
        }
        .top-bar {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            height: 64px;
            background: rgba(3,3,3,0.95);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid var(--mist);
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 2rem;
            z-index: 100;
        }
        .brand { font-size: 0.875rem; font-weight: 700; letter-spacing: 0.2em; text-transform: uppercase; }
        .user-info { display: flex; align-items: center; gap: 1rem; }
        .user-name { color: var(--ghost); font-size: 0.875rem; }
        .logout-btn {
            background: transparent;
            border: 1px solid var(--mist);
            color: var(--ghost);
            padding: 0.5rem 1rem;
            font-family: inherit;
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.3s;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .logout-btn:hover { border-color: var(--alert); color: var(--alert); }
        .dashboard {
            padding: 6rem 2rem 2rem;
            max-width: 1200px;
            margin: 0 auto;
        }
        .welcome-section {
            margin-bottom: 3rem;
            animation: slideUp 0.8s var(--ease-out-expo);
        }
        @keyframes slideUp {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .welcome-title {
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, #fff 0%, #888 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .welcome-sub { color: var(--ghost); font-size: 0.875rem; }
        .stats-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 3rem;
        }
        .stat-box {
            background: var(--carbon);
            border: 1px solid var(--mist);
            padding: 1.5rem;
            animation: slideUp 0.8s var(--ease-out-expo) 0.1s both;
        }
        .stat-label {
            font-size: 0.75rem;
            color: var(--ghost);
            text-transform: uppercase;
            letter-spacing: 0.1em;
            margin-bottom: 0.5rem;
        }
        .stat-value {
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--pure);
        }
        .stat-value.warning { color: var(--warn); }
        .stat-value.success { color: var(--neon); }
        
        .panel {
            background: var(--carbon);
            border: 1px solid var(--mist);
            padding: 2rem;
            margin-bottom: 2rem;
            animation: slideUp 0.8s var(--ease-out-expo) 0.2s both;
        }
        .panel-header {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--mist);
        }
        .panel-accent {
            width: 3px;
            height: 1.5rem;
            background: var(--neon);
            box-shadow: 0 0 10px var(--neon);
        }
        .panel-title {
            font-size: 0.875rem;
            font-weight: 600;
            letter-spacing: 0.1em;
            text-transform: uppercase;
        }
        .form-grid {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr auto;
            gap: 1rem;
            align-items: end;
        }
        .input-group { position: relative; }
        .input-group label {
            display: block;
            font-size: 0.6875rem;
            color: var(--ghost);
            text-transform: uppercase;
            letter-spacing: 0.1em;
            margin-bottom: 0.5rem;
        }
        .input-group input {
            width: 100%;
            height: 48px;
            background: var(--void);
            border: 1px solid var(--mist);
            color: var(--pure);
            padding: 0 1rem;
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
            outline: none;
            transition: all 0.3s;
        }
        .input-group input:focus {
            border-color: var(--neon);
            box-shadow: 0 0 20px rgba(0,255,136,0.1);
        }
        .btn-primary {
            height: 48px;
            padding: 0 1.5rem;
            background: var(--neon);
            color: var(--void);
            border: none;
            font-family: inherit;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            cursor: pointer;
            transition: all 0.3s;
            white-space: nowrap;
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(0,255,136,0.2);
        }
        .btn-primary:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }
        .info-text {
            font-size: 0.75rem;
            color: var(--ghost);
            margin-top: 1rem;
            padding: 0.75rem;
            background: rgba(255,255,255,0.03);
            border-left: 2px solid var(--neon);
        }
        .search-bar {
            margin-bottom: 1.5rem;
            display: flex;
            justify-content: flex-end;
        }
        .search-input {
            width: 300px;
            height: 40px;
            background: var(--void);
            border: 1px solid var(--mist);
            color: var(--pure);
            padding: 0 1rem;
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
            outline: none;
            transition: all 0.3s;
        }
        .search-input:focus {
            border-color: var(--neon);
            box-shadow: 0 0 20px rgba(0,255,136,0.1);
        }
        .table-container {
            overflow-x: auto;
            animation: slideUp 0.8s var(--ease-out-expo) 0.3s both;
        }
        .data-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.8125rem;
        }
        .data-table th {
            text-align: left;
            padding: 1rem;
            color: var(--ghost);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-size: 0.6875rem;
            border-bottom: 1px solid var(--mist);
            background: rgba(255,255,255,0.02);
        }
        .data-table td {
            padding: 1rem;
            border-bottom: 1px solid var(--mist);
            color: var(--pure);
        }
        .data-table tr:last-child td { border-bottom: none; }
        .data-table tr:hover { background: rgba(255,255,255,0.02); }
        .mono { font-family: 'Courier New', monospace; letter-spacing: 0.02em; }
        .badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            font-size: 0.6875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-radius: 2px;
        }
        .badge.active { background: rgba(0,255,136,0.1); color: var(--neon); }
        .badge.expired { background: rgba(255,71,87,0.1); color: var(--alert); }
        .delete-btn {
            background: transparent;
            border: 1px solid rgba(255,71,87,0.3);
            color: var(--alert);
            padding: 0.4rem 1rem;
            font-family: inherit;
            font-size: 0.6875rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .delete-btn:hover {
            background: rgba(255,71,87,0.1);
            border-color: var(--alert);
            transform: scale(1.02);
        }
        .notification {
            position: fixed;
            top: 5rem;
            right: 2rem;
            background: var(--graphite);
            border: 1px solid var(--mist);
            border-left: 3px solid var(--neon);
            padding: 1rem 1.5rem;
            font-size: 0.875rem;
            z-index: 10000;
            transform: translateX(400px);
            opacity: 0;
            transition: all 0.4s var(--ease-out-expo);
        }
        .notification.show { transform: translateX(0); opacity: 1; }
        .notification.error { border-left-color: var(--alert); }
        .empty-state {
            padding: 3rem;
            text-align: center;
            color: var(--ghost);
            font-size: 0.875rem;
        }
        @media (max-width: 768px) {
            .form-grid { grid-template-columns: 1fr; }
            .btn-primary { width: 100%; }
            .stats-row { grid-template-columns: 1fr; }
            .search-bar { justify-content: stretch; }
            .search-input { width: 100%; }
        }
        ::selection { background: rgba(0,255,136,0.2); color: var(--pure); }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: var(--void); }
        ::-webkit-scrollbar-thumb { background: var(--steel); border-radius: 3px; }
    </style>
</head>
<body>
    <div class="noise-overlay"></div>
    
    <header class="top-bar">
        <div class="brand">DELETE HEX</div>
        <div class="user-info">
            <span class="user-name" id="currentUser">Loading...</span>
            <button class="logout-btn" onclick="logout()">Logout</button>
        </div>
    </header>

    <main class="dashboard">
        <section class="welcome-section">
            <h1 class="welcome-title">Hardware ID Management</h1>
            <p class="welcome-sub">Manage your device registrations and access credentials</p>
        </section>

        <div class="stats-row">
            <div class="stat-box">
                <div class="stat-label">Account Status</div>
                <div class="stat-value success" id="accountStatus">Active</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Days Remaining</div>
                <div class="stat-value" id="daysRemaining">-</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Registered Devices</div>
                <div class="stat-value" id="deviceCount">0</div>
            </div>
        </div>

        <section class="panel">
            <div class="panel-header">
                <div class="panel-accent"></div>
                <h2 class="panel-title">Register New Device</h2>
            </div>
            <form id="hwidForm" onsubmit="return addHWID(event)">
                <div class="form-grid">
                    <div class="input-group">
                        <label>Hardware ID (HWID)</label>
                        <input type="text" id="hwidInput" placeholder="Enter HWID..." required spellcheck="false">
                    </div>
                    <div class="input-group">
                        <label>Duration (Days)</label>
                        <input type="number" id="durationInput" placeholder="30" min="1" required>
                    </div>
                    <div class="input-group">
                        <label>Executable Name</label>
                        <input type="text" id="exeInput" placeholder="APP_NAME" required spellcheck="false">
                    </div>
                    <button type="submit" class="btn-primary" id="submitBtn">Register</button>
                </div>
                <div class="info-text" id="maxDaysInfo">
                    You can register HWID for maximum <span id="maxDays">0</span> days based on your account expiration.
                </div>
            </form>
        </section>

        <section class="panel" style="padding: 0; overflow: hidden;">
            <div class="panel-header" style="margin: 0; padding: 1.5rem 2rem; background: var(--graphite);">
                <div class="panel-accent"></div>
                <h2 class="panel-title">Your Registered Devices</h2>
            </div>
            <div class="search-bar" style="padding: 1rem 2rem 0 2rem;">
                <input type="text" id="searchInput" class="search-input" placeholder="🔍 Search HWID or Executable..." onkeyup="filterHWIDs()">
            </div>
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>HWID</th>
                            <th>Executable</th>
                            <th>Added Date</th>
                            <th>Expires</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="hwidTableBody">
                        <tr><td colspan="6" class="empty-state">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
        </section>
    </main>

    <div id="notification" class="notification"></div>

    <script>
        let userData = null;
        let maxAllowedDays = 0;
        let allHWIDs = [];

        document.addEventListener('DOMContentLoaded', async () => {
            await loadUserData();
            await loadUserHWIDs();
        });

        async function loadUserData() {
            try {
                const res = await fetch('/api/user/profile');
                const data = await res.json();
                
                if (data.status === 'ok') {
                    userData = data;
                    document.getElementById('currentUser').textContent = data.username;
                    document.getElementById('daysRemaining').textContent = data.remaining_days + ' days';
                    document.getElementById('maxDays').textContent = data.remaining_days;
                    document.getElementById('deviceCount').textContent = data.hwid_count;
                    
                    maxAllowedDays = data.remaining_days;
                    document.getElementById('durationInput').max = maxAllowedDays;
                    
                    if (data.remaining_days <= 3) {
                        document.getElementById('daysRemaining').classList.add('warning');
                    }
                } else {
                    window.location.href = '/';
                }
            } catch (err) {
                window.location.href = '/';
            }
        }

        async function loadUserHWIDs() {
            try {
                const res = await fetch('/api/user/hwids');
                const data = await res.json();
                
                if (data.status === 'ok') {
                    allHWIDs = data.hwids;
                    renderHWIDTable(allHWIDs);
                    document.getElementById('deviceCount').textContent = allHWIDs.length;
                }
            } catch (err) {
                console.error('Failed to load HWIDs');
            }
        }

        function renderHWIDTable(hwids) {
            const tbody = document.getElementById('hwidTableBody');
            if (hwids.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No devices registered</td></tr>';
                return;
            }
            
            tbody.innerHTML = hwids.map(h => `
                <tr>
                    <td class="mono">${escapeHtml(h.hwid)}</td>
                    <td>${escapeHtml(h.exe_name)}</td>
                    <td>${h.added_at}</td>
                    <td>${h.expire_date}</td>
                    <td><span class="badge ${h.status}">${h.status.toUpperCase()}</span></td>
                    <td><button class="delete-btn" onclick="deleteHWID('${escapeHtml(h.hwid)}')">Delete</button></td>
                </tr>
            `).join('');
        }

        function filterHWIDs() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const filtered = allHWIDs.filter(h => 
                h.hwid.toLowerCase().includes(searchTerm) || 
                h.exe_name.toLowerCase().includes(searchTerm)
            );
            renderHWIDTable(filtered);
        }

        async function deleteHWID(hwid) {
            if (!confirm(`Are you sure you want to delete HWID: ${hwid}?`)) return;
            
            try {
                const res = await fetch(`/api/user/hwid/${encodeURIComponent(hwid)}`, {
                    method: 'DELETE'
                });
                const data = await res.json();
                
                if (data.status === 'ok') {
                    showNotification('HWID deleted successfully');
                    await loadUserHWIDs();
                    await loadUserData();
                } else {
                    showNotification(data.message || 'Failed to delete HWID', 'error');
                }
            } catch (err) {
                showNotification('Failed to delete HWID', 'error');
            }
        }

        async function addHWID(e) {
            e.preventDefault();
            const btn = document.getElementById('submitBtn');
            const hwid = document.getElementById('hwidInput').value.trim();
            const duration = parseInt(document.getElementById('durationInput').value);
            const exeName = document.getElementById('exeInput').value.trim();
            
            if (duration > maxAllowedDays) {
                showNotification(`Maximum allowed duration is ${maxAllowedDays} days`, 'error');
                return false;
            }
            
            btn.disabled = true;
            btn.textContent = 'Registering...';
            
            try {
                const res = await fetch('/api/user/hwid', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        hwid: hwid,
                        duration: duration,
                        exe_name: exeName
                    })
                });
                
                const data = await res.json();
                
                if (data.status === 'ok') {
                    showNotification('Device registered successfully');
                    document.getElementById('hwidForm').reset();
                    await loadUserHWIDs();
                    await loadUserData();
                } else {
                    showNotification(data.message, 'error');
                }
            } catch (err) {
                showNotification('Failed to register device', 'error');
            } finally {
                btn.disabled = false;
                btn.textContent = 'Register';
            }
            return false;
        }

        async function logout() {
            await fetch('/api/logout', {method: 'POST'});
            window.location.href = '/';
        }

        function showNotification(msg, type = 'success') {
            const notif = document.getElementById('notification');
            notif.textContent = msg;
            notif.className = 'notification ' + (type === 'error' ? 'error' : '');
            setTimeout(() => notif.classList.add('show'), 10);
            setTimeout(() => notif.classList.remove('show'), 3000);
        }

        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/[&<>]/g, function(m) {
                if (m === '&') return '&amp;';
                if (m === '<') return '&lt;';
                if (m === '>') return '&gt;';
                return m;
            });
        }
    </script>
</body>
</html>'''

# Admin control panel UI
ADMIN_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DELETE HEX — Admin Command</title>
    <style>
        :root {
            --void: #030303;
            --carbon: #080808;
            --graphite: #111111;
            --steel: #1a1a1a;
            --iron: #252525;
            --mist: rgba(255, 255, 255, 0.03);
            --fog: rgba(255, 255, 255, 0.06);
            --ghost: rgba(255, 255, 255, 0.5);
            --pure: #ffffff;
            --neon: #00ff88;
            --alert: #ff4757;
            --warn: #ffa502;
            --ease-out-expo: cubic-bezier(0.16, 1, 0.3, 1);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        html { font-size: 16px; -webkit-font-smoothing: antialiased; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--void);
            color: var(--pure);
            min-height: 100vh;
            line-height: 1.6;
        }
        .noise-overlay {
            position: fixed;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 400 400' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.8' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)'/%3E%3C/svg%3E");
            opacity: 0.02;
            pointer-events: none;
            z-index: 1000;
            animation: grain 8s steps(10) infinite;
        }
        @keyframes grain {
            0%, 100% { transform: translate(0, 0); }
            10% { transform: translate(-5%, -5%); }
            20% { transform: translate(-10%, 5%); }
            30% { transform: translate(5%, -10%); }
            40% { transform: translate(-5%, 15%); }
            50% { transform: translate(-10%, 5%); }
            60% { transform: translate(15%, 0); }
            70% { transform: translate(0, 10%); }
            80% { transform: translate(-15%, 0); }
            90% { transform: translate(10%, 5%); }
        }
        .top-bar {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            height: 64px;
            background: rgba(3,3,3,0.95);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid var(--mist);
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 2rem;
            z-index: 100;
        }
        .brand-lockup {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 0.875rem;
            font-weight: 600;
            letter-spacing: 0.05em;
        }
        .divider { opacity: 0.3; }
        .section-title { color: var(--ghost); font-weight: 500; }
        .admin-badge {
            background: var(--neon);
            color: var(--void);
            padding: 0.25rem 0.5rem;
            font-size: 0.625rem;
            font-weight: 700;
            letter-spacing: 0.1em;
            margin-left: 0.5rem;
        }
        .header-actions {
            display: flex;
            align-items: center;
            gap: 1.5rem;
        }
        .status-indicator {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.75rem;
            color: var(--ghost);
        }
        .status-dot {
            width: 6px;
            height: 6px;
            background: var(--neon);
            border-radius: 50%;
            box-shadow: 0 0 10px var(--neon);
            animation: pulse 2s infinite;
        }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        .logout-btn {
            background: transparent;
            border: 1px solid var(--mist);
            color: var(--ghost);
            padding: 0.5rem 1rem;
            font-family: inherit;
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.3s;
        }
        .logout-btn:hover { border-color: var(--alert); color: var(--alert); }
        .dashboard {
            padding: 6rem 2rem 2rem;
            max-width: 1400px;
            margin: 0 auto;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }
        .stat-card {
            background: var(--carbon);
            border: 1px solid var(--mist);
            padding: 1.5rem;
            transition: all 0.3s var(--ease-out-expo);
        }
        .stat-card:hover {
            transform: translateY(-2px);
            border-color: var(--fog);
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }
        .stat-card.warning { border-color: rgba(255, 160, 2, 0.3); }
        .stat-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }
        .stat-label {
            font-size: 0.75rem;
            color: var(--ghost);
            letter-spacing: 0.1em;
            text-transform: uppercase;
        }
        .stat-icon { color: var(--neon); font-size: 0.875rem; }
        .stat-value { font-size: 2.5rem; font-weight: 700; letter-spacing: -0.02em; margin-bottom: 0.5rem; }
        .stat-footer { font-size: 0.8125rem; color: var(--ghost); }
        .control-panel {
            background: var(--carbon);
            border: 1px solid var(--mist);
            padding: 2rem;
            margin-bottom: 2.5rem;
        }
        .panel-header {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1.5rem;
        }
        .panel-accent { width: 3px; height: 1.5rem; background: var(--pure); }
        .panel-title { font-size: 0.875rem; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase; }
        .create-form .form-row {
            display: flex;
            gap: 1rem;
            align-items: flex-end;
            flex-wrap: wrap;
        }
        .input-group { position: relative; flex: 1; min-width: 200px; }
        .input-group input {
            width: 100%;
            height: 48px;
            background: var(--void);
            border: 1px solid var(--mist);
            color: var(--pure);
            padding: 0 1rem;
            font-family: inherit;
            font-size: 0.875rem;
            outline: none;
            transition: all 0.3s var(--ease-out-expo);
        }
        .input-group input:focus { border-color: var(--pure); background: rgba(255,255,255,0.02); }
        .action-btn {
            height: 48px;
            padding: 0 1.5rem;
            border: 1px solid var(--mist);
            background: transparent;
            color: var(--ghost);
            font-family: inherit;
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            cursor: pointer;
            transition: all 0.3s var(--ease-out-expo);
            white-space: nowrap;
        }
        .action-btn:hover { border-color: var(--fog); color: var(--pure); background: rgba(255,255,255,0.03); }
        .action-btn.primary { background: var(--pure); color: var(--void); border-color: var(--pure); }
        .action-btn.primary:hover { background: var(--neon); border-color: var(--neon); }
        .action-btn.warning { border-color: var(--warn); color: var(--warn); }
        .action-btn.warning:hover { background: rgba(255, 165, 2, 0.1); }
        .data-section { background: var(--carbon); border: 1px solid var(--mist); margin-bottom: 1.5rem; }
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1.25rem 1.5rem;
            background: var(--graphite);
            border-bottom: 1px solid var(--mist);
        }
        .header-title { display: flex; align-items: center; gap: 1rem; }
        .header-title h3 { font-size: 0.875rem; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase; }
        .count-badge {
            background: var(--mist);
            padding: 0.25rem 0.75rem;
            font-size: 0.6875rem;
            color: var(--ghost);
            border-radius: 2px;
        }
        .search-area {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--mist);
            display: flex;
            justify-content: flex-end;
        }
        .admin-search {
            width: 300px;
            height: 40px;
            background: var(--void);
            border: 1px solid var(--mist);
            color: var(--pure);
            padding: 0 1rem;
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
            outline: none;
            transition: all 0.3s;
        }
        .admin-search:focus {
            border-color: var(--neon);
            box-shadow: 0 0 20px rgba(0,255,136,0.1);
        }
        .table-container { overflow-x: auto; }
        .data-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.8125rem;
        }
        .data-table th {
            text-align: left;
            padding: 1rem 1.5rem;
            color: var(--ghost);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-size: 0.6875rem;
            border-bottom: 1px solid var(--mist);
            background: rgba(255,255,255,0.02);
        }
        .data-table td { padding: 1rem 1.5rem; border-bottom: 1px solid var(--mist); color: var(--pure); }
        .data-table tr:last-child td { border-bottom: none; }
        .data-table tr:hover { background: rgba(255,255,255,0.02); }
        .data-table tr.expired { opacity: 0.5; }
        .mono { font-family: 'Courier New', monospace; letter-spacing: 0.02em; }
        .badge { background: var(--mist); padding: 0.25rem 0.5rem; font-size: 0.75rem; border-radius: 2px; }
        .status-badge {
            padding: 0.25rem 0.75rem;
            font-size: 0.6875rem;
            font-weight: 700;
            letter-spacing: 0.05em;
            border-radius: 2px;
            text-transform: uppercase;
        }
        .status-badge.active { background: rgba(0, 255, 136, 0.1); color: var(--neon); }
        .status-badge.expired { background: rgba(255, 71, 87, 0.1); color: var(--alert); }
        .icon-btn {
            width: 28px;
            height: 28px;
            border: 1px solid var(--mist);
            background: transparent;
            color: var(--ghost);
            font-size: 1.25rem;
            line-height: 1;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s;
        }
        .icon-btn:hover { border-color: currentColor; transform: scale(1.1); }
        .icon-btn.danger { color: var(--alert); }
        .icon-btn.danger:hover { background: rgba(255, 71, 87, 0.1); box-shadow: 0 0 20px rgba(255, 71, 87, 0.2); }
        .icon-btn.warning { color: var(--warn); border-color: rgba(255, 165, 2, 0.3); }
        .icon-btn.warning:hover { background: rgba(255, 165, 2, 0.1); box-shadow: 0 0 20px rgba(255, 165, 2, 0.2); }
        .edit-btn {
            background: transparent;
            border: 1px solid var(--mist);
            color: var(--ghost);
            padding: 0.4rem 0.8rem;
            font-family: inherit;
            font-size: 0.6875rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-right: 0.5rem;
        }
        .edit-btn:hover {
            border-color: var(--neon);
            color: var(--neon);
            background: rgba(0,255,136,0.05);
        }
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.8);
            backdrop-filter: blur(4px);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            opacity: 0;
            visibility: hidden;
            transition: all 0.3s var(--ease-out-expo);
        }
        .modal-overlay.active {
            opacity: 1;
            visibility: visible;
        }
        .modal {
            background: var(--carbon);
            border: 1px solid var(--mist);
            padding: 2rem;
            width: 90%;
            max-width: 400px;
            transform: translateY(20px);
            transition: transform 0.3s var(--ease-out-expo);
        }
        .modal-overlay.active .modal {
            transform: translateY(0);
        }
        .modal h3 {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            letter-spacing: -0.01em;
        }
        .modal .input-group {
            margin-bottom: 1.5rem;
        }
        .modal-actions {
            display: flex;
            gap: 1rem;
            justify-content: flex-end;
        }
        .modal-actions .action-btn {
            min-width: 80px;
        }
        .notification {
            position: fixed;
            top: 5rem;
            right: 2rem;
            background: var(--graphite);
            border: 1px solid var(--mist);
            padding: 1rem 1.5rem;
            font-size: 0.875rem;
            z-index: 10000;
            transform: translateX(400px);
            opacity: 0;
            transition: all 0.4s var(--ease-out-expo);
            border-left: 3px solid var(--neon);
        }
        .notification.show { transform: translateX(0); opacity: 1; }
        .notification.error { border-left-color: var(--alert); }
        .notification.warning { border-left-color: var(--warn); }
        .device-info {
            font-size: 0.75rem;
            color: var(--ghost);
            margin-top: 0.25rem;
        }
        .device-locked { color: var(--neon); }
        .device-unlocked { color: var(--warn); }
        .empty-state { padding: 3rem; text-align: center; color: var(--ghost); font-size: 0.875rem; }
        ::selection { background: rgba(0,255,136,0.2); color: var(--pure); }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: var(--void); }
        ::-webkit-scrollbar-thumb { background: var(--steel); border-radius: 3px; }
        @media (max-width: 968px) {
            .create-form .form-row { flex-direction: column; }
            .input-group { width: 100%; }
            .action-btn { width: 100%; }
            .stats-grid { grid-template-columns: 1fr; }
            .data-table { font-size: 0.75rem; }
            .data-table th, .data-table td { padding: 0.75rem; }
            .search-area { justify-content: stretch; }
            .admin-search { width: 100%; }
        }
    </style>
</head>
<body>
    <div class="noise-overlay"></div>
    
    <header class="top-bar">
        <div class="brand-lockup">
            <span>DELETE HEX</span>
            <span class="divider">/</span>
            <span class="section-title">Admin Control</span>
            <span class="admin-badge">ADMIN</span>
        </div>
        <div class="header-actions">
            <div class="status-indicator">
                <span class="status-dot"></span>
                <span>System Online</span>
            </div>
            <button class="logout-btn" onclick="logout()">Terminate Session</button>
        </div>
    </header>

    <main class="dashboard">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-header"><span class="stat-label">Total Users</span><span class="stat-icon">◈</span></div>
                <div class="stat-value" id="stat-total-users">0</div>
                <div class="stat-footer"><span id="stat-active-users">0</span> Active</div>
            </div>
            <div class="stat-card">
                <div class="stat-header"><span class="stat-label">Total HWIDs</span><span class="stat-icon">◉</span></div>
                <div class="stat-value" id="stat-total-hwids">0</div>
                <div class="stat-footer"><span id="stat-active-hwids">0</span> Active</div>
            </div>
            <div class="stat-card warning">
                <div class="stat-header"><span class="stat-label">Expired</span><span class="stat-icon">⚠</span></div>
                <div class="stat-value" id="stat-expired">0</div>
                <div class="stat-footer">Requires Attention</div>
            </div>
        </div>

        <section class="control-panel">
            <div class="panel-header">
                <div class="panel-accent"></div>
                <h2 class="panel-title">Create New User</h2>
            </div>
            <form class="create-form" onsubmit="return createUser(event)">
                <div class="form-row">
                    <div class="input-group">
                        <input type="text" id="new-username" placeholder="Username" required autocomplete="off">
                    </div>
                    <div class="input-group" style="flex: 0 0 150px;">
                        <input type="number" id="new-duration" placeholder="Days" value="30" min="1" max="365" required>
                    </div>
                    <button type="submit" class="action-btn primary">Create User</button>
                </div>
            </form>
        </section>

        <section class="data-section">
            <div class="section-header">
                <div class="header-title">
                    <h3>User Registry</h3>
                    <span class="count-badge" id="user-count">0 entries</span>
                </div>
            </div>
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Created</th>
                            <th>Duration</th>
                            <th>Expires</th>
                            <th>Remaining</th>
                            <th>HWIDs</th>
                            <th>Status</th>
                            <th>Device Lock</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="users-tbody">
                        <tr><td colspan="9" class="empty-state">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
        </section>

        <section class="data-section">
            <div class="section-header">
                <div class="header-title">
                    <h3>Hardware ID Registry</h3>
                    <span class="count-badge" id="hwid-count">0 entries</span>
                </div>
            </div>
            <div class="search-area">
                <input type="text" id="adminHwidSearch" class="admin-search" placeholder="🔍 Search HWID, User or Executable..." onkeyup="filterAdminHWIDs()">
            </div>
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>HWID</th>
                            <th>User</th>
                            <th>Executable</th>
                            <th>Added</th>
                            <th>Expires</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="hwids-tbody">
                        <tr><td colspan="7" class="empty-state">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
        </section>
    </main>

    <div class="modal-overlay" id="editModal">
        <div class="modal">
            <h3>Edit User License</h3>
            <form onsubmit="return submitEdit(event)">
                <input type="hidden" id="edit-username">
                <div class="input-group">
                    <label style="display:block; margin-bottom:0.5rem; color:var(--ghost); font-size:0.75rem;">New Duration (days)</label>
                    <input type="number" id="edit-duration" min="1" max="365" required style="width:100%; height:48px; background:var(--void); border:1px solid var(--mist); color:var(--pure); padding:0 1rem;">
                </div>
                <div class="modal-actions">
                    <button type="button" class="action-btn" onclick="closeEditModal()">Cancel</button>
                    <button type="submit" class="action-btn primary">Update</button>
                </div>
            </form>
        </div>
    </div>

    <div id="notification" class="notification"></div>

    <script>
        let allUsers = [];
        let allHWIDs = [];

        document.addEventListener('DOMContentLoaded', loadData);
        
        async function loadData() {
            try {
                const statsRes = await fetch('/api/admin/stats');
                const statsData = await statsRes.json();
                if (statsData.status === 'ok') {
                    document.getElementById('stat-total-users').textContent = statsData.stats.total_users;
                    document.getElementById('stat-active-users').textContent = statsData.stats.active_users;
                    document.getElementById('stat-total-hwids').textContent = statsData.stats.total_hwids;
                    document.getElementById('stat-active-hwids').textContent = statsData.stats.active_hwids;
                    document.getElementById('stat-expired').textContent = statsData.stats.expired_hwids;
                }
                
                const usersRes = await fetch('/api/admin/users');
                const usersData = await usersRes.json();
                if (usersData.status === 'ok') {
                    allUsers = usersData.users;
                    renderUsers(allUsers);
                }
                
                const hwidsRes = await fetch('/api/admin/hwids');
                const hwidsData = await hwidsRes.json();
                if (hwidsData.status === 'ok') {
                    allHWIDs = hwidsData.hwids;
                    renderHWIDs(allHWIDs);
                }
            } catch (err) {
                showNotification('Failed to load data', 'error');
            }
        }

        function renderUsers(users) {
            document.getElementById('user-count').textContent = users.length + ' entries';
            const tbody = document.getElementById('users-tbody');
            if (users.length === 0) {
                tbody.innerHTML = '<tr><td colspan="9" class="empty-state">No users found</td></tr>';
                return;
            }
            tbody.innerHTML = users.map(user => {
                const isDeviceLocked = user.device_fingerprint ? true : false;
                const deviceClass = isDeviceLocked ? 'device-locked' : 'device-unlocked';
                const deviceText = isDeviceLocked ? 'LOCKED' : 'UNLOCKED';
                const deviceShort = isDeviceLocked ? user.device_fingerprint.substring(0, 8) + '...' : 'Not Set';
                
                return `
                <tr class="${user.is_expired ? 'expired' : ''}">
                    <td class="mono">${escapeHtml(user.username)}</td>
                    <td>${user.created_at}</td>
                    <td>${user.duration_days} days</td>
                    <td>${user.expire_date}</td>
                    <td style="${user.remaining_days <= 3 ? 'color: var(--warn)' : ''}">${user.remaining_days} days</td>
                    <td><span class="badge">${user.active_hwids}/${user.total_hwids}</span></td>
                    <td><span class="status-badge ${user.is_expired ? 'expired' : 'active'}">${user.is_expired ? 'EXPIRED' : 'ACTIVE'}</span></td>
                    <td>
                        <div class="${deviceClass}">${deviceText}</div>
                        <div class="device-info">${deviceShort}</div>
                    </td>
                    <td>
                        <button class="edit-btn" onclick="openEditModal('${escapeHtml(user.username)}', ${user.duration_days})" title="Edit">✎</button>
                        <button class="icon-btn warning" onclick="resetDevice('${escapeHtml(user.username)}')" title="Reset Device Lock">◉</button>
                        <button class="icon-btn danger" onclick="deleteUser('${escapeHtml(user.username)}')" title="Delete">×</button>
                    </td>
                </tr>
            `}).join('');
        }

        function renderHWIDs(hwids) {
            document.getElementById('hwid-count').textContent = hwids.length + ' entries';
            const tbody = document.getElementById('hwids-tbody');
            if (hwids.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No HWIDs found</td></tr>';
                return;
            }
            tbody.innerHTML = hwids.map(hwid => `
                <tr class="${hwid.status === 'expired' ? 'expired' : ''}">
                    <td class="mono">${escapeHtml(hwid.hwid)}</td>
                    <td>${escapeHtml(hwid.username)}</td>
                    <td>${escapeHtml(hwid.exe_name)}</td>
                    <td>${hwid.added_at}</td>
                    <td>${hwid.expire_date}</td>
                    <td><span class="status-badge ${hwid.status}">${hwid.status.toUpperCase()}</span></td>
                    <td><button class="icon-btn danger" onclick="deleteHWID('${escapeHtml(hwid.hwid)}')" title="Remove">×</button></td>
                </tr>
            `).join('');
        }

        function filterAdminHWIDs() {
            const searchTerm = document.getElementById('adminHwidSearch').value.toLowerCase();
            const filtered = allHWIDs.filter(h => 
                h.hwid.toLowerCase().includes(searchTerm) || 
                h.username.toLowerCase().includes(searchTerm) ||
                h.exe_name.toLowerCase().includes(searchTerm)
            );
            renderHWIDs(filtered);
        }

        async function createUser(e) {
            e.preventDefault();
            const username = document.getElementById('new-username').value.trim();
            const duration = parseInt(document.getElementById('new-duration').value);
            
            try {
                const res = await fetch('/api/admin/users', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username, duration_days: duration})
                });
                const data = await res.json();
                if (data.status === 'ok') {
                    showNotification('User created successfully');
                    document.getElementById('new-username').value = '';
                    loadData();
                } else {
                    showNotification(data.message, 'error');
                }
            } catch (err) {
                showNotification('Failed to create user', 'error');
            }
            return false;
        }

        async function deleteUser(username) {
            if (!confirm(`Delete user "${username}" and all their HWIDs?`)) return;
            try {
                const res = await fetch(`/api/admin/users/${username}`, {method: 'DELETE'});
                const data = await res.json();
                if (data.status === 'ok') {
                    showNotification(data.message);
                    loadData();
                } else {
                    showNotification(data.message, 'error');
                }
            } catch (err) {
                showNotification('Failed to delete user', 'error');
            }
        }

        async function resetDevice(username) {
            if (!confirm(`Reset device lock for user "${username}"?\n\nThis will allow them to login from a new device.`)) return;
            try {
                const res = await fetch(`/api/admin/users/${username}/reset-device`, {method: 'POST'});
                const data = await res.json();
                if (data.status === 'ok') {
                    showNotification(data.message, 'success');
                    loadData();
                } else {
                    showNotification(data.message, 'error');
                }
            } catch (err) {
                showNotification('Failed to reset device lock', 'error');
            }
        }

        async function deleteHWID(hwid) {
            if (!confirm(`Remove HWID "${hwid}"?`)) return;
            try {
                const res = await fetch(`/api/admin/hwids/${hwid}`, {method: 'DELETE'});
                const data = await res.json();
                if (data.status === 'ok') {
                    showNotification('HWID removed');
                    loadData();
                } else {
                    showNotification(data.message, 'error');
                }
            } catch (err) {
                showNotification('Failed to remove HWID', 'error');
            }
        }

        function openEditModal(username, currentDuration) {
            document.getElementById('edit-username').value = username;
            document.getElementById('edit-duration').value = currentDuration;
            document.getElementById('editModal').classList.add('active');
        }

        function closeEditModal() {
            document.getElementById('editModal').classList.remove('active');
        }

        async function submitEdit(e) {
            e.preventDefault();
            const username = document.getElementById('edit-username').value;
            const duration = parseInt(document.getElementById('edit-duration').value);

            try {
                const res = await fetch(`/api/admin/users/${username}`, {
                    method: 'PUT',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({duration_days: duration})
                });
                const data = await res.json();
                if (data.status === 'ok') {
                    showNotification('User updated successfully');
                    closeEditModal();
                    loadData();
                } else {
                    showNotification(data.message, 'error');
                }
            } catch (err) {
                showNotification('Failed to update user', 'error');
            }
            return false;
        }

        async function logout() {
            await fetch('/api/admin/logout', {method: 'POST'});
            window.location.href = '/';
        }

        function showNotification(message, type = 'success') {
            const notif = document.getElementById('notification');
            notif.textContent = message;
            notif.className = 'notification ' + (type === 'error' ? 'error' : type === 'warning' ? 'warning' : '');
            setTimeout(() => notif.classList.add('show'), 10);
            setTimeout(() => notif.classList.remove('show'), 3000);
        }

        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/[&<>]/g, function(m) {
                if (m === '&') return '&amp;';
                if (m === '<') return '&lt;';
                if (m === '>') return '&gt;';
                return m;
            });
        }
    </script>
</body>
</html>'''

# --- Application Routes & API Endpoints ---

@app.route('/')
def index():
    return render_template_string(LOGIN_HTML)

@app.route('/admin')
@admin_required
def admin_page():
    return render_template_string(ADMIN_HTML)

@app.route('/dashboard')
@user_required
def user_dashboard():
    return render_template_string(USER_DASHBOARD_HTML)

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('.', filename)

@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No data received"}), 400
            
        username = data.get('username', '').strip().lower()
        
        if not username:
            return jsonify({"status": "error", "message": "Username required"}), 400
        
        fingerprint, ip, ua = get_device_fingerprint()
        
        if username == ADMIN_USERNAME:
            session.permanent = True
            session['admin_logged_in'] = True
            session['admin_user'] = username
            session['role'] = 'admin'
            add_log("ADMIN_LOGIN", username=username, details=f"IP: {ip}")
            return jsonify({"status": "ok", "role": "admin"})
        
        users_data = read_json(USERS_FILE)
        user = next((u for u in users_data['users'] if u['username'] == username), None)
        
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404
        
        today = datetime.now().date()
        expire_date = datetime.strptime(user['expire_date'], "%Y-%m-%d").date()
        
        if today > expire_date:
            return jsonify({"status": "error", "message": "Account expired"}), 403
        
        stored_fingerprint = user.get('device_fingerprint')
        
        if stored_fingerprint is None or stored_fingerprint == "":
            user['device_fingerprint'] = fingerprint
            user['first_login_ip'] = ip
            user['first_login_ua'] = ua[:100]
            user['first_login_date'] = today.isoformat()
            
            if write_json(USERS_FILE, users_data):
                add_log("DEVICE_REGISTERED", username=username, details=f"Fingerprint: {fingerprint[:16]}..., IP: {ip}")
            else:
                return jsonify({"status": "error", "message": "Failed to register device"}), 500
                
        elif stored_fingerprint != fingerprint:
            add_log("DEVICE_REJECTED", username=username, details=f"Expected: {stored_fingerprint[:16]}..., Got: {fingerprint[:16]}..., IP: {ip}")
            return jsonify({
                "status": "error", 
                "message": "Device not authorized. This account is locked to another device. Contact admin."
            }), 403
        
        session.permanent = True
        session['user_logged_in'] = True
        session['username'] = username
        session['role'] = 'user'
        session['fingerprint'] = fingerprint
        add_log("USER_LOGIN", username=username, details=f"IP: {ip}")
        return jsonify({"status": "ok", "role": "user"})
        
    except Exception as e:
        print(f"Login error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    try:
        session.clear()
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/admin/stats')
@admin_required
def get_stats():
    try:
        users_data = read_json(USERS_FILE)
        hwid_data = read_json(HWID_FILE)
        today = datetime.now().date()
        
        total_users = len(users_data['users'])
        active_users = sum(1 for u in users_data['users'] 
                          if datetime.strptime(u['expire_date'], "%Y-%m-%d").date() >= today)
        
        total_hwids = len(hwid_data['hwids'])
        active_hwids = 0
        expired_hwids = 0
        for h in hwid_data['hwids']:
            expire = datetime.strptime(h['expire_date'], "%Y-%m-%d").date()
            if expire >= today and h.get('status') != 'expired':
                active_hwids += 1
            else:
                expired_hwids += 1
        
        return jsonify({
            "status": "ok",
            "stats": {
                "total_users": total_users,
                "active_users": active_users,
                "total_hwids": total_hwids,
                "active_hwids": active_hwids,
                "expired_hwids": expired_hwids
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/admin/users')
@admin_required
def get_users():
    try:
        users_data = read_json(USERS_FILE)
        hwid_data = read_json(HWID_FILE)
        today = datetime.now().date()
        
        enriched = []
        for user in users_data['users']:
            expire_date = datetime.strptime(user['expire_date'], "%Y-%m-%d").date()
            remaining = (expire_date - today).days
            
            user_hwids = [h for h in hwid_data['hwids'] if h['username'] == user['username']]
            active = sum(1 for h in user_hwids if h['status'] == 'active')
            
            enriched.append({
                **user,
                "remaining_days": max(0, remaining),
                "is_expired": remaining <= 0,
                "total_hwids": len(user_hwids),
                "active_hwids": active
            })
        
        return jsonify({"status": "ok", "users": enriched})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/admin/users', methods=['POST'])
@admin_required
def create_user():
    try:
        data = request.get_json()
        username = data.get('username', '').strip().lower()
        duration = int(data.get('duration_days', 30))
        
        if not username:
            return jsonify({"status": "error", "message": "Username required"}), 400
        
        if username == ADMIN_USERNAME:
            return jsonify({"status": "error", "message": "Reserved username"}), 409
        
        users_data = read_json(USERS_FILE)
        if any(u['username'] == username for u in users_data['users']):
            return jsonify({"status": "error", "message": "User already exists"}), 409
        
        today = datetime.now().date()
        expire = today + timedelta(days=duration)
        
        new_user = {
            "username": username,
            "created_at": today.isoformat(),
            "duration_days": duration,
            "expire_date": expire.isoformat(),
            "status": "active",
            "device_fingerprint": None,
            "first_login_ip": None,
            "first_login_ua": None,
            "first_login_date": None
        }
        
        users_data['users'].append(new_user)
        
        if write_json(USERS_FILE, users_data):
            add_log("USER_CREATED", username=username)
            return jsonify({"status": "ok", "user": new_user})
        return jsonify({"status": "error", "message": "Failed to save"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/admin/users/<username>', methods=['DELETE'])
@admin_required
def delete_user(username):
    try:
        username = username.lower()
        if username == ADMIN_USERNAME:
            return jsonify({"status": "error", "message": "Cannot delete admin"}), 403
        
        users_data = read_json(USERS_FILE)
        hwid_data = read_json(HWID_FILE)
        
        user_found = False
        for i, u in enumerate(users_data['users']):
            if u['username'] == username:
                users_data['users'].pop(i)
                user_found = True
                break
        
        if not user_found:
            return jsonify({"status": "error", "message": "User not found"}), 404
        
        hwids_removed = sum(1 for h in hwid_data['hwids'] if h['username'] == username)
        hwid_data['hwids'] = [h for h in hwid_data['hwids'] if h['username'] != username]
        
        if write_json(USERS_FILE, users_data) and write_json(HWID_FILE, hwid_data):
            add_log("USER_DELETED", username=username)
            return jsonify({"status": "ok", "message": f"User deleted. Removed {hwids_removed} HWIDs."})
        return jsonify({"status": "error", "message": "Failed to delete"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/admin/users/<username>', methods=['PUT'])
@admin_required
def update_user(username):
    try:
        username = username.lower()
        if username == ADMIN_USERNAME:
            return jsonify({"status": "error", "message": "Cannot edit admin user"}), 403

        data = request.get_json()
        if not data or 'duration_days' not in data:
            return jsonify({"status": "error", "message": "duration_days required"}), 400

        try:
            new_duration = int(data['duration_days'])
            if new_duration < 1:
                raise ValueError
        except ValueError:
            return jsonify({"status": "error", "message": "Invalid duration"}), 400

        users_data = read_json(USERS_FILE)
        user_index = None
        for i, u in enumerate(users_data['users']):
            if u['username'] == username:
                user_index = i
                break

        if user_index is None:
            return jsonify({"status": "error", "message": "User not found"}), 404

        today = datetime.now().date()
        new_expire = today + timedelta(days=new_duration)

        users_data['users'][user_index]['duration_days'] = new_duration
        users_data['users'][user_index]['expire_date'] = new_expire.isoformat()

        if write_json(USERS_FILE, users_data):
            add_log("USER_UPDATED", username=username, details=f"New duration: {new_duration} days")
            return jsonify({"status": "ok", "message": "User updated successfully"})
        else:
            return jsonify({"status": "error", "message": "Failed to save changes"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/admin/users/<username>/reset-device', methods=['POST'])
@admin_required
def reset_device_lock(username):
    try:
        username = username.lower()
        if username == ADMIN_USERNAME:
            return jsonify({"status": "error", "message": "Cannot reset admin device"}), 403
        
        users_data = read_json(USERS_FILE)
        user_index = None
        for i, u in enumerate(users_data['users']):
            if u['username'] == username:
                user_index = i
                break
        
        if user_index is None:
            return jsonify({"status": "error", "message": "User not found"}), 404
        
        old_fp = users_data['users'][user_index].get('device_fingerprint', 'None')
        users_data['users'][user_index]['device_fingerprint'] = None
        users_data['users'][user_index]['first_login_ip'] = None
        users_data['users'][user_index]['first_login_ua'] = None
        
        if write_json(USERS_FILE, users_data):
            add_log("DEVICE_RESET", username=username, details=f"Old FP: {old_fp[:16] if old_fp else 'None'}...")
            return jsonify({"status": "ok", "message": f"Device lock reset for {username}. They can now login from a new device."})
        return jsonify({"status": "error", "message": "Failed to reset device"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/admin/hwids')
@admin_required
def get_hwids():
    try:
        hwid_data = read_json(HWID_FILE)
        today = datetime.now().date()
        
        for h in hwid_data['hwids']:
            expire = datetime.strptime(h['expire_date'], "%Y-%m-%d").date()
            if today > expire:
                h['status'] = 'expired'
        
        return jsonify({"status": "ok", "hwids": hwid_data['hwids']})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/admin/hwids/<hwid>', methods=['DELETE'])
@admin_required
def delete_hwid(hwid):
    try:
        hwid_data = read_json(HWID_FILE)
        found = False
        username = None
        for i, h in enumerate(hwid_data['hwids']):
            if h['hwid'] == hwid:
                username = h['username']
                hwid_data['hwids'].pop(i)
                found = True
                break
        
        if not found:
            return jsonify({"status": "error", "message": "HWID not found"}), 404
        
        if write_json(HWID_FILE, hwid_data):
            add_log("HWID_REMOVED", username=username, hwid=hwid)
            return jsonify({"status": "ok"})
        return jsonify({"status": "error", "message": "Failed to remove"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/admin/logout', methods=['POST'])
def admin_logout():
    try:
        session.clear()
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/user/profile')
@user_required
def user_profile():
    try:
        username = session.get('username')
        if not username:
            return jsonify({"status": "error", "message": "Not logged in"}), 401
        
        users_data = read_json(USERS_FILE)
        hwid_data = read_json(HWID_FILE)
        today = datetime.now().date()
        
        user = next((u for u in users_data['users'] if u['username'] == username), None)
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404
        
        expire_date = datetime.strptime(user['expire_date'], "%Y-%m-%d").date()
        remaining = (expire_date - today).days
        
        user_hwids = [h for h in hwid_data['hwids'] if h['username'] == username]
        
        return jsonify({
            "status": "ok",
            "username": username,
            "expire_date": user['expire_date'],
            "remaining_days": max(0, remaining),
            "hwid_count": len(user_hwids),
            "is_expired": remaining <= 0,
            "device_locked": user.get('device_fingerprint') is not None
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/user/hwids')
@user_required
def user_hwids():
    try:
        username = session.get('username')
        hwid_data = read_json(HWID_FILE)
        today = datetime.now().date()
        
        user_hwids = [h for h in hwid_data['hwids'] if h['username'] == username]
        
        for h in user_hwids:
            expire = datetime.strptime(h['expire_date'], "%Y-%m-%d").date()
            if today > expire:
                h['status'] = 'expired'
        
        return jsonify({"status": "ok", "hwids": user_hwids})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/user/hwid', methods=['POST'])
@user_required
def add_user_hwid():
    try:
        username = session.get('username')
        data = request.get_json()
        hwid = data.get('hwid', '').strip()
        requested_days = int(data.get('duration', 30))
        exe_name = data.get('exe_name', 'UNKNOWN').strip()
        
        if not hwid:
            return jsonify({"status": "error", "message": "HWID required"}), 400
        
        if not exe_name:
            return jsonify({"status": "error", "message": "Executable name required"}), 400
        
        users_data = read_json(USERS_FILE)
        hwid_data = read_json(HWID_FILE)
        
        user = next((u for u in users_data['users'] if u['username'] == username), None)
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404
        
        today = datetime.now().date()
        user_expire = datetime.strptime(user['expire_date'], "%Y-%m-%d").date()
        
        if today > user_expire:
            return jsonify({"status": "error", "message": "User license expired"}), 403
        
        remaining = (user_expire - today).days
        
        if requested_days > remaining:
            return jsonify({
                "status": "error",
                "message": f"You can add HWID for maximum {remaining} days only.",
                "max_allowed": remaining
            }), 400
        
        if any(h['hwid'] == hwid for h in hwid_data['hwids']):
            return jsonify({"status": "error", "message": "HWID already registered"}), 409
        
        hwid_expire = today + timedelta(days=requested_days)
        
        new_hwid = {
            "username": username,
            "hwid": hwid,
            "exe_name": exe_name,
            "added_at": today.isoformat(),
            "expire_date": hwid_expire.isoformat(),
            "status": "active"
        }
        
        hwid_data['hwids'].append(new_hwid)
        
        if write_json(HWID_FILE, hwid_data):
            add_log("HWID_ADDED", username=username, hwid=hwid, details=f"Exe: {exe_name}, Days: {requested_days}")
            return jsonify({
                "status": "ok",
                "message": "HWID added successfully",
                "expire_date": hwid_expire.isoformat()
            })
        return jsonify({"status": "error", "message": "Failed to save"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/user/hwid/<hwid>', methods=['DELETE'])
@user_required
def delete_user_hwid(hwid):
    try:
        username = session.get('username')
        hwid_data = read_json(HWID_FILE)
        
        found = False
        for i, h in enumerate(hwid_data['hwids']):
            if h['hwid'] == hwid and h['username'] == username:
                hwid_data['hwids'].pop(i)
                found = True
                break
        
        if not found:
            return jsonify({"status": "error", "message": "HWID not found or not owned by you"}), 404
        
        if write_json(HWID_FILE, hwid_data):
            add_log("HWID_DELETED_BY_USER", username=username, hwid=hwid)
            return jsonify({"status": "ok", "message": "HWID deleted successfully"})
        return jsonify({"status": "error", "message": "Failed to delete HWID"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/auth/validate', methods=['POST'])
def validate_hwid():
    try:
        data = request.get_json()
        hwid = data.get('hwid', '').strip()
        
        if not hwid:
            return jsonify({"status": "error", "message": "HWID required"}), 400
        
        hwid_data = read_json(HWID_FILE)
        today = datetime.now().date()
        
        found = None
        for h in hwid_data['hwids']:
            if h['hwid'] == hwid:
                found = h
                break
        
        if not found:
            add_log("AUTH_FAIL", hwid=hwid, details="HWID not found")
            return jsonify({
                "status": "error",
                "message": "Your HWID Doesn't Match With Our Database or Expired"
            }), 403
        
        expire = datetime.strptime(found['expire_date'], "%Y-%m-%d").date()
        
        if today > expire:
            found['status'] = 'expired'
            write_json(HWID_FILE, hwid_data)
            add_log("AUTH_FAIL", username=found['username'], hwid=hwid, details="Expired")
            return jsonify({
                "status": "error",
                "message": "Your HWID Doesn't Match With Our Database or Expired"
            }), 403
        
        users_data = read_json(USERS_FILE)
        user = next((u for u in users_data['users'] if u['username'] == found['username']), None)
        
        if not user:
            return jsonify({"status": "error", "message": "User account not found"}), 403
        
        user_expire = datetime.strptime(user['expire_date'], "%Y-%m-%d").date()
        if today > user_expire:
            return jsonify({"status": "error", "message": "User license expired"}), 403
        
        add_log("AUTH_SUCCESS", username=found['username'], hwid=hwid)
        return jsonify({
            "status": "ok",
            "message": "Access Granted",
            "expire_date": found['expire_date'],
            "exe_name": found['exe_name'],
            "username": found['username']
        })
            
    except Exception as e:
        add_log("AUTH_ERROR", details=str(e))
        return jsonify({"status": "error", "message": "Server error"}), 500

# Background Discord bot integration
bot_start_lock = threading.Lock()
with bot_start_lock:
    if not os.environ.get("BOT_STARTED"):
        os.environ["BOT_STARTED"] = "1"
        try:
            import bot
            bot_thread = threading.Thread(target=bot.main, daemon=True)
            bot_thread.start()
            print("Discord bot worker started.")
        except Exception as e:
            print(f"Bot worker start failed: {e}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print("Starting authentication server...")
    print(f"Listening on port {port}")

    use_https = os.environ.get('USE_HTTPS', 'false').lower() == 'true'
    if use_https:
        ssl_context = ('cert.pem', 'key.pem')
        app.run(host='0.0.0.0', port=port, debug=False, ssl_context=ssl_context)
    else:
        app.run(host='0.0.0.0', port=port, debug=False)
