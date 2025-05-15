# handler.py

import sqlite3, json, datetime
import pyotp
from cryptography.fernet import Fernet
from pydantic import BaseModel

DB_PATH = "data.db"
SECRET_KEY = Fernet.generate_key()
cipher = Fernet(SECRET_KEY)

class Payload(BaseModel):
    user_id: str
    password: str
    code_2fa: str

def handle(req):
    data = Payload.model_validate_json(req)

    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()

        cur.execute("SELECT password, created_at FROM passwords WHERE user_id=?", (data.user_id,))
        row = cur.fetchone()
        if not row:
            return {"error": "Utilisateur introuvable"}

        encrypted_password, created_at = row
        stored_password = cipher.decrypt(encrypted_password.encode()).decode()

        # Vérifier expiration
        date_obj = datetime.datetime.strptime(created_at, "%Y-%m-%d")
        if (datetime.datetime.now() - date_obj).days > 180:
            conn.execute("UPDATE passwords SET expired=1 WHERE user_id=?", (data.user_id,))
            return {"status": "expired", "message": "Réinitialisation requise"}

        # Vérif mot de passe
        if data.password != stored_password:
            return {"error": "Mot de passe invalide"}

        cur.execute("SELECT secret FROM twofa WHERE user_id=?", (data.user_id,))
        row = cur.fetchone()
        if not row:
            return {"error": "2FA non configuré"}

        decrypted_secret = cipher.decrypt(row[0].encode()).decode()
        totp = pyotp.TOTP(decrypted_secret)

        if not totp.verify(data.code_2fa):
            return {"error": "Code 2FA invalide"}

        return {"status": "ok", "message": "Authentification réussie"}
