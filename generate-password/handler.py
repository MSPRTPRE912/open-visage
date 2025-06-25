import json
import secrets, string, qrcode, base64, io, psycopg2, os
from cryptography.fernet import Fernet
from pydantic import BaseModel

with open("/var/openfaas/secrets/password-db", "r") as f:
    PASSWORD_DB = f.read().strip().encode()

PG_CONN = {
    "dbname": os.environ["db_name"],
    "user": os.environ["db_user"],
    "password": PASSWORD_DB,
    "host": os.environ["db_host"],
    "port": os.environ["db_port"]
}

with open("/var/openfaas/secrets/secret-key", "r") as f:
    SECRET_KEY = f.read().strip().encode()

cipher = Fernet(SECRET_KEY)

class Payload(BaseModel):
    email: str
    first_name: str
    last_name: str

def generate_password(length=24):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

def handle(event, context):
    body = event.body
    data = Payload.model_validate_json(body)

    password = generate_password()
    encrypted_password = cipher.encrypt(password.encode()).decode()

    img = qrcode.make(password)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_b64 = base64.b64encode(buffer.getvalue()).decode()

    conn = psycopg2.connect(**PG_CONN)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            first_name TEXT,
            last_name TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            email TEXT,
            password TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)

    cur.execute("INSERT INTO users (email, first_name, last_name) VALUES (%s, %s, %s) ON CONFLICT (email) DO NOTHING",
                (data.email, data.first_name, data.last_name))
    cur.execute("INSERT INTO passwords (email, password) VALUES (%s, %s)",
                (data.email, encrypted_password))

    conn.commit()
    cur.close()
    conn.close()

    return {
        "statusCode": 200,
        "body": json.dumps({
            "password_qrcode": qr_b64
        }),
        "headers": {"Content-Type": "application/json"}
    }
