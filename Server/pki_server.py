import pymysql
import hashlib
from flask import Flask, request, jsonify

DB_HOST = 'localhost'
DB_USER = 'bahaa'
DB_PASS = 'Stockfish'
DB_NAME = 'openbox_pki'

app = Flask(__name__)

def init_db():
    """Bootstraps the database and table with password security features."""
    try:
        conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS)
        with conn.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
        conn.commit()
        conn.close()

        conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME)
        with conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS identities (
                    UserID INT AUTO_INCREMENT PRIMARY KEY,
                    UserUniqueName VARCHAR(255) UNIQUE NOT NULL,
                    PasswordHash VARCHAR(255) NOT NULL,
                    PublicKey TEXT NOT NULL,
                    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UpdatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_username (UserUniqueName)
                ) ENGINE=InnoDB;
            """)
        conn.commit()
        conn.close()
        print("[+] Database initialized successfully with security extensions.")
    except Exception as e:
        print(f"[-] Database initialization failed: {e}")

def get_db_connection():
    return pymysql.connect(
        host=DB_HOST, 
        user=DB_USER, 
        password=DB_PASS, 
        database=DB_NAME, 
        cursorclass=pymysql.cursors.DictCursor
    )

@app.route('/register', methods=['POST'])
def register_identity():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data or 'public_key' not in data:
        return jsonify({"error": "Missing payload fields."}), 400
        
    username = data['username'].strip()
    password = data['password'].strip()
    pub_key = data['public_key'].strip()
    
    # 1. Compute Password Hash
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    # 2. Compute Public Key Hash (Fingerprint)
    pubkey_hash = hashlib.sha256(pub_key.encode('utf-8')).hexdigest()

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            sql = """
                INSERT INTO identities (UserUniqueName, PasswordHash, PublicKey, PublicKeyHash) 
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE 
                    PasswordHash = VALUES(PasswordHash), 
                    PublicKey = VALUES(PublicKey),
                    PublicKeyHash = VALUES(PublicKeyHash)
            """
            cursor.execute(sql, (username, hashed_password, pub_key, pubkey_hash))
        conn.commit()
        return jsonify({"status": "success", "message": "Identity registered with public key tracking."}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals() and conn.open:
            conn.close()

@app.route('/login', methods=['POST'])
def login_identity():
    """Verifies user credentials against stored credential records."""
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Missing username or password in payload."}), 400

    username = data['username'].strip()
    password = data['password'].strip()
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT PasswordHash FROM identities WHERE UserUniqueName = %s", (username,))
            result = cursor.fetchone()
            
        if result and result['PasswordHash'] == hashed_password:
            return jsonify({"status": "success", "message": "Authentication successful."}), 200
        else:
            return jsonify({"error": "Invalid username or password credentials."}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals() and conn.open:
            conn.close()

@app.route('/lookup/<username>', methods=['GET'])
def lookup_key(username):
    """Fetches a target recipient's public key string for asymmetric encapsulation."""
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT PublicKey FROM identities WHERE UserUniqueName = %s", (username,))
            result = cursor.fetchone()
            
        if result:
            return jsonify({"status": "success", "public_key": result['PublicKey']}), 200
        else:
            return jsonify({"error": "User identity not found."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals() and conn.open:
            conn.close()

if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', port=5000, debug=False)