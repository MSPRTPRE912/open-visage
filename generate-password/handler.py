import secrets, string, qrcode, base64, io, sqlite3
from cryptography.fernet import Fernet
from pydantic import BaseModel

DB_PATH = "data.db"
SECRET_KEY = Fernet.generate_key()  # À stocker ailleurs (Vault, etc.)
cipher = Fernet(SECRET_KEY)

class Payload(BaseModel):
    user_id: str

def generate_password(length=24):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

def handle(req):
    data = Payload.model_validate_json(req)
    password = generate_password()
    encrypted_password = cipher.encrypt(password.encode()).decode()

    img = qrcode.make(password)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_b64 = base64.b64encode(buffer.getvalue()).decode()

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS passwords (user_id TEXT, password TEXT)")
        conn.execute("INSERT INTO passwords (user_id, password) VALUES (?, ?)", (data.user_id, encrypted_password))
        conn.commit()

    return {"password_qrcode": qr_b64}
