from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Date, Time
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from pydantic import BaseModel
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware
import os
import logging
from fastapi.responses import JSONResponse
# Laden der Umgebungsvariablen
from dotenv import load_dotenv
load_dotenv()

# Initialisieren des Loggings
logging.basicConfig(level=logging.DEBUG)

# Passwort-Hashing-Konfiguration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Datenbankverbindung
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
Base = declarative_base()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# FastAPI-App initialisieren
app = FastAPI()

# CORS-Middleware konfigurieren
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://zutrittssystemweb.onrender.com"],  # Frontend-Domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Datenbank-Modelle
class Benutzer(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)

# Initialisiere die Datenbank
Base.metadata.create_all(bind=engine)

# API-Datenmodelle
class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

# Hilfsfunktionen
def get_password_hash(password):
    """Hashing-Funktion für Passwörter"""
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    """Überprüfen eines Passworts gegen einen Hash"""
    return pwd_context.verify(plain_password, hashed_password)

def get_user_by_username(username: str):
    """Benutzer anhand des Benutzernamens aus der Datenbank abfragen"""
    db = SessionLocal()
    user = db.query(Benutzer).filter(Benutzer.username == username).first()
    db.close()
    return user

# Routen
@app.post("/register")
def register_user(register_request: RegisterRequest):
    """Benutzerregistrierung"""
    db = SessionLocal()
    if db.query(Benutzer).filter(Benutzer.username == register_request.username).first():
        db.close()
        raise HTTPException(status_code=400, detail="Benutzername bereits vergeben")
    
    hashed_password = get_password_hash(register_request.password)
    new_user = Benutzer(username=register_request.username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.close()
    
    logging.debug(f"Benutzer {register_request.username} erfolgreich registriert")
    return {"message": "Benutzer erfolgreich registriert"}

@app.post("/login")
def login_user(login_request: LoginRequest):
    logging.debug(f"Login attempt: {login_request.username}")
    db = SessionLocal()
    user = db.query(Benutzer).filter(Benutzer.username == login_request.username).first()
    db.close()

    if not user:
        logging.debug("User not found.")
        return JSONResponse(status_code=401, content={"detail": "Ungültiger Benutzername oder Passwort"})

    logging.debug(f"User found: {user.username}")

    if not verify_password(login_request.password, user.hashed_password):
        logging.debug("Password mismatch.")
        return JSONResponse(status_code=401, content={"detail": "Ungültiger Benutzername oder Passwort"})

    logging.debug(f"Password verified for user {user.username}.")
    return JSONResponse(status_code=200, content={"message": f"Willkommen, {login_request.username}!", "user_id": user.id})