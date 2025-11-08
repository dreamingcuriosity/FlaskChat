from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import threading

app = Flask(__name__)
CORS(app)

# Store messages in memory
messages = []
message_id_counter = 0
message_lock = threading.Lock()

# Store active users (username -> {last_seen, public_key})
active_users = {}
user_lock = threading.Lock()

def update_user_activity(username: str, public_key=None):
    """Update last seen time and public key for a user"""
    with user_lock:
        if username not in active_users:
            active_users[username] = {}
        active_users[username]['last_seen'] = datetime.now()
        if public_key:
            active_users[username]['public_key'] = public_key

def get_active_users(timeout_seconds: int = 300):
    """Get list of users active within timeout period"""
    now = datetime.now()
    with user_lock:
        return [
            username for username, data in active_users.items()
            if (now - data['last_seen']).total_seconds() < timeout_seconds
        ]

@app.route('/register', methods=['POST'])
def register_user():
    """Register username and public key"""
    data = request.get_json()

    if not data or 'username' not in data or 'public_key' not in data:
        return jsonify({'error': 'Missing username or public_key'}), 400

    username = data['username'].strip()
    public_key = data['public_key']

    if not username or len(username) > 20:
        return jsonify({'error': 'Invalid username length'}), 400

    update_user_activity(username, public_key)

    print(f"\033[32m[REGISTER]\033[0m User '{username}' joined with public key")
    print(f"\033[33m[PUBLIC KEY]\033[0m {public_key['x'][:20]}...")

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

@app.route('/public_keys', methods=['GET'])
def get_public_keys():
    """Get public keys for all active users"""
    users = get_active_users()
    
    with user_lock:
        keys = {
            username: active_users[username]['public_key']
            for username in users
            if 'public_key' in active_users[username]
        }
    
    return jsonify({
        'keys': keys
    })

@app.route('/message', methods=['POST'])
def handle_message():
    """Handle encrypted messages"""
    global message_id_counter

    data = request.get_json()

    if not data or 'username' not in data or 'encrypted_for' not in data:
        return jsonify({'error': 'Missing username or encrypted_for'}), 400

    username = data['username']
    encrypted_for = data['encrypted_for']  # Dict of {recipient: encrypted_message}

    update_user_activity(username)

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    print(f"\033[35m[{timestamp}] [{username}]\033[0m")
    print(f"\033[36m[ENCRYPTED FOR]\033[0m {len(encrypted_for)} recipients")

    # Store separate message for each recipient
    with message_lock:
        for recipient, encrypted_msg in encrypted_for.items():
            message_id_counter += 1
            message = {
                'id': message_id_counter,
                'username': username,
                'recipient': recipient,
                'encrypted': encrypted_msg,
                'timestamp': timestamp
            }
            messages.append(message)

        # Keep only last 200 messages
        if len(messages) > 200:
            messages[:] = messages[-200:]

    return jsonify({
        'status': 'ok',
        'id': message_id_counter
    })

@app.route('/messages', methods=['GET'])
def get_messages():
    """Get messages for the requesting user since a specific ID"""
    since_id = request.args.get('since', 0, type=int)
    for_user = request.args.get('user', None)

    with message_lock:
        if for_user:
            # Return only messages intended for this user
            new_messages = [
                msg for msg in messages 
                if msg['id'] > since_id and msg['recipient'] == for_user
            ]
        else:
            # Return all messages (for backward compatibility)
            new_messages = [msg for msg in messages if msg['id'] > since_id]

    return jsonify({
        'messages': new_messages
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    print("\033[32m[SERVER] Starting E2E Encrypted Chat Server\033[0m")
    print("\033[33m[SERVER] Using ECDH key exchange + AES-GCM encryption\033[0m")
    print("\033[33m[SERVER] Server never sees plaintext messages!\033[0m")
    print()
    app.run(host='0.0.0.0', port=8000, debug=True, threaded=True)
