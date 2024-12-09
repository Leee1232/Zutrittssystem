from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from database import engine  # Datenbankverbindung importieren

app = FastAPI()

class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/login")
def login(request: LoginRequest):
    query = text("""
        SELECT id, email
        FROM users
        WHERE email = :email
          AND hashed_password = crypt(:password, hashed_password)
    """)
    
    with engine.connect() as conn:
        result = conn.execute(query, {"email": request.email, "password": request.password}).fetchone()
    
    if not result:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    return {"message": "Login successful", "user_id": result["id"], "email": result["email"]}
