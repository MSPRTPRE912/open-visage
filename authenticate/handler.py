# handler.py

import json
import psycopg2, datetime
import pyotp, secrets, qrcode, base64, string, io, os
from cryptography.fernet import Fernet
from pydantic import BaseModel

PG_CONN = {
    "dbname": os.environ["db_name"],
    "user": os.environ["db_user"],
    "password": "Pa$$w0rd",
    "host": os.environ["db_host"],
    "port": os.environ["db_port"]
}

with open("/var/openfaas/secrets/secret-key", "r") as f:
    SECRET_KEY = f.read().strip().encode()

cipher = Fernet(SECRET_KEY)

class Payload(BaseModel):
    email: str
    password: str
    code_2fa: str

def generate_password(length=24):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

def handle(event, context):
    body = event.body
    data = Payload.model_validate_json(body)

    conn = psycopg2.connect(**PG_CONN)
    cur = conn.cursor()

    cur.execute("SELECT password, created_at FROM passwords WHERE email = %s", (data.email,))
    row = cur.fetchone()
    if not row:
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": "Utilisateur introuvable"
            }),
            "headers": {"Content-Type": "application/json"}
        }   

    encrypted_password, created_at = row
    stored_password = cipher.decrypt(encrypted_password.encode()).decode()

    # Vérif mot de passe
    if data.password != stored_password:
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": "Mot de passe invalide"
            }),
            "headers": {"Content-Type": "application/json"}
        }
    
    cur.execute("SELECT secret FROM twofa WHERE email = %s", (data.email,))
    row = cur.fetchone()
    if not row:
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": "2FA non configuré"
            }),
            "headers": {"Content-Type": "application/json"}
        }

    decrypted_secret = cipher.decrypt(row[0].encode()).decode()
    totp = pyotp.TOTP(decrypted_secret)

    if not totp.verify(data.code_2fa, valid_window=1):
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": "Code 2FA invalide"
            }),
            "headers": {"Content-Type": "application/json"}
        }

    # Vérifier expiration
    if (datetime.datetime.now() - created_at).days > 180:
        password = generate_password()
        encrypted_password = cipher.encrypt(password.encode()).decode()

        img_password = qrcode.make(password)
        buffer_password = io.BytesIO()
        img_password.save(buffer_password, format="PNG")
        qr_b64_password = base64.b64encode(buffer_password.getvalue()).decode()

        cur.execute("UPDATE passwords SET password = %s, created_at = %s WHERE email = %s",
                (encrypted_password, datetime.datetime.now(), data.email))

        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=data.email, issuer_name="COFRAP")

        img_otp = qrcode.make(uri)
        buffer_otp = io.BytesIO()
        img_otp.save(buffer_otp, format="PNG")
        qr_b64_otp = base64.b64encode(buffer_otp.getvalue()).decode()

        encrypted_secret = cipher.encrypt(secret.encode()).decode()

        cur.execute("UPDATE twofa SET secret = %s WHERE email = %s",
                (encrypted_secret, data.email))

        return {
            "statusCode": 200,
            "body": json.dumps({
                "status": "expired",
                "password_qrcode": qr_b64_password,
                "2fa_qrcode": qr_b64_otp,

            }),
            "headers": {"Content-Type": "application/json"}
        }
    
    cur.execute("SELECT email, first_name, last_name FROM users WHERE email = %s", (data.email,))
    row = cur.fetchone()
    if not row:
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": "Utilisateur introuvable"
            }),
            "headers": {"Content-Type": "application/json"}
        }
    
    email, first_name, last_name = row
    
    return {
        "statusCode": 200,
        "body": json.dumps({
            "status": "ok",
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
        }),
        "headers": {"Content-Type": "application/json"}
    }
