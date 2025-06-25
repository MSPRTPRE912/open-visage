import json
import pyotp, qrcode, base64, io, psycopg2, os
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

def handle(event, context):
    body = event.body
    data = Payload.model_validate_json(body)

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=data.email, issuer_name="COFRAP")

    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_b64 = base64.b64encode(buffer.getvalue()).decode()

    encrypted_secret = cipher.encrypt(secret.encode()).decode()

    conn = psycopg2.connect(**PG_CONN)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS twofa (
            email TEXT,
            secret TEXT
        )
    """)

    cur.execute("INSERT INTO twofa (email, secret) VALUES (%s, %s)",
                (data.email, encrypted_secret))

    conn.commit()
    cur.close()
    conn.close()

    return {
        "statusCode": 200,
        "body": json.dumps({
            "2fa_qrcode": qr_b64
        }),
        "headers": {"Content-Type": "application/json"}
    }
