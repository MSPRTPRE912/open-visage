import pyotp, qrcode, base64, io, sqlite3
from cryptography.fernet import Fernet
from pydantic import BaseModel

DB_PATH = "data.db"
SECRET_KEY = Fernet.generate_key()
cipher = Fernet(SECRET_KEY)

class Payload(BaseModel):
    user_id: str

def handle(req):
    data = Payload.model_validate_json(req)
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=data.user_id, issuer_name="COFRAP")

    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_b64 = base64.b64encode(buffer.getvalue()).decode()

    encrypted_secret = cipher.encrypt(secret.encode()).decode()

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS twofa (user_id TEXT, secret TEXT)")
        conn.execute("INSERT INTO twofa (user_id, secret) VALUES (?, ?)", (data.user_id, encrypted_secret))
        conn.commit()

    return {"2fa_qrcode": qr_b64}
