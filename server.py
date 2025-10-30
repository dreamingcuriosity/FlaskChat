from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
from flask import send_from_directory
import threading
import secrets
import hashlib
import base64

app = Flask(__name__)
CORS(app)

# Store messages in memory
messages = []
message_id_counter = 0
message_lock = threading.Lock()

# Store active users (username -> last_seen timestamp)
active_users = {}
user_lock = threading.Lock()

# Store user public keys (if needed for future E2E encryption)
user_keys = {}

# ===== SECURE ENCRYPTION SYSTEM =====
class SecureChat:
    """Custom cryptographic system using XOR with key stretching and authentication"""

    @staticmethod
    def derive_key(password: str, salt: bytes = None, iterations: int = 100000) -> tuple:
        """Derive a secure key from password using PBKDF2"""
        if salt is None:
            salt = secrets.token_bytes(32)

        # Use PBKDF2 for key derivation
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=64)
        return key, salt

    @staticmethod
    def encrypt(plaintext: str, key: bytes) -> str:
        """Encrypt with AES-like XOR stream cipher + authentication"""
        # Convert text to bytes
        data = plaintext.encode('utf-8')

        # Generate random IV (initialization vector)
        iv = secrets.token_bytes(16)

        # Generate keystream using HMAC-based stream
        encrypted = bytearray()
        counter = 0

        for i in range(len(data)):
            if i % 32 == 0:
                # Generate new keystream block
                keystream = hashlib.sha256(key + iv + counter.to_bytes(8, 'big')).digest()
                counter += 1

            encrypted.append(data[i] ^ keystream[i % 32])

        # Create HMAC for authentication
        mac = hashlib.sha256(key + iv + bytes(encrypted)).digest()[:16]

        # Combine IV + encrypted data + MAC
        result = iv + bytes(encrypted) + mac

        # Encode to base64 for transmission
        return base64.b64encode(result).decode('ascii')

    @staticmethod
    def decrypt(ciphertext: str, key: bytes) -> str:
        """Decrypt and verify authentication"""
        try:
            # Decode from base64
            data = base64.b64decode(ciphertext.encode('ascii'))

            # Extract components
            iv = data[:16]
            mac = data[-16:]
            encrypted = data[16:-16]

            # Verify MAC
            expected_mac = hashlib.sha256(key + iv + encrypted).digest()[:16]
            if not secrets.compare_digest(mac, expected_mac):
                raise ValueError("Authentication failed - message may be tampered")

            # Decrypt
            decrypted = bytearray()
            counter = 0

            for i in range(len(encrypted)):
                if i % 32 == 0:
                    keystream = hashlib.sha256(key + iv + counter.to_bytes(8, 'big')).digest()
                    counter += 1

                decrypted.append(encrypted[i] ^ keystream[i % 32])

            return bytes(decrypted).decode('utf-8')

        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

# Initialize with a shared secret (in production, use proper key exchange)
SHARED_SECRET = "7a888fc7afba508fe27f6c7193ed54298535b4b24373e5007054d75d2ba7f4c8e1b9ecc99758a9c5ac3df61303c7bf"
ENCRYPTION_KEY, SALT = SecureChat.derive_key(SHARED_SECRET)

# ===== USERNAME MANAGEMENT =====
def update_user_activity(username: str):
    """Update last seen time for a user"""
    with user_lock:
        active_users[username] = datetime.now()

def get_active_users(timeout_seconds: int = 300):
    """Get list of users active within timeout period"""
    now = datetime.now()
    with user_lock:
        return [
            username for username, last_seen in active_users.items()
            if (now - last_seen).total_seconds() < timeout_seconds
        ]

# ===== FLASK ROUTES =====
@app.route('/register', methods=['POST'])
def register_user():
    """Register or update a username"""
    data = request.get_json()
    
    if not data or 'username' not in data:
        return jsonify({'error': 'Missing username'}), 400
    
    username = data['username'].strip()
    
    if not username or len(username) > 20:
        return jsonify({'error': 'Invalid username length'}), 400
    
    update_user_activity(username)
    
    print(f"\033[32m[REGISTER]\033[0m User '{username}' joined")
    
    return jsonify({
        'status': 'ok',
        'username': username
    })

@app.route('/users', methods=['GET'])
def get_users():
    """Get list of active users"""
    users = get_active_users()
    return jsonify({
        'users': users,
        'count': len(users)
    })

@app.route('/message', methods=['POST'])
def handle_message():
    """Receive encrypted message from a user"""
    global message_id_counter

    data = request.get_json()

    if not data or 'encrypted' not in data or 'username' not in data:
        return jsonify({'error': 'Missing encrypted message or username'}), 400

    encrypted_msg = data['encrypted']
    username = data['username']

    try:
        # Decrypt incoming message
        decrypted_msg = SecureChat.decrypt(encrypted_msg, ENCRYPTION_KEY)

        # Update user activity
        update_user_activity(username)

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        print(f"\033[35m[{timestamp}] [{username}]\033[0m")
        print(f"\033[33m[ENCRYPTED]\033[0m {encrypted_msg[:80]}{'...' if len(encrypted_msg) > 80 else ''}")
        print(f"\033[36m[DECRYPTED]\033[0m {decrypted_msg}")
        print()

        # Store message
        with message_lock:
            message_id_counter += 1
            message = {
                'id': message_id_counter,
                'username': username,
                'encrypted': encrypted_msg,
                'decrypted': decrypted_msg,
                'timestamp': timestamp
            }
            messages.append(message)

            # Keep only last 100 messages
            if len(messages) > 100:
                messages.pop(0)

        return jsonify({
            'status': 'ok',
            'id': message_id_counter
        })

    except Exception as e:
        print(f"\033[31m[ERROR]\033[0m Failed to decrypt message: {str(e)}")
        return jsonify({'error': 'Decryption failed'}), 400

@app.route('/messages', methods=['GET'])
def get_messages():
    """Get messages since a specific ID"""
    since_id = request.args.get('since', 0, type=int)

    with message_lock:
        new_messages = [msg for msg in messages if msg['id'] > since_id]

    return jsonify({
        'messages': new_messages
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'ok'})

@app.route('/salt', methods=['GET'])
def get_salt():
    """Provide salt for client key derivation"""
    return jsonify({
        'salt': base64.b64encode(SALT).decode('ascii')
    })
@app.route('/')
def index():
    # Adjust path to where your HTML file is actually stored
    return send_from_directory('/sdcard', 'index.html')
if __name__ == '__main__':
    print("\033[32m[SERVER] Starting Secure Multi-User Chat Server...\033[0m")
    print(f"\033[33m[SERVER] Using shared secret for encryption\033[0m")
    print(f"\033[33m[SERVER] Salt: {base64.b64encode(SALT).decode('ascii')[:20]}...\033[0m")
    print()
    app.run(host='0.0.0.0', port=8000, debug=True, threaded=True)
