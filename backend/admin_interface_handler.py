from fastapi import FastAPI, HTTPException
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Date, Time
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from pydantic import BaseModel
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware
from typing import List
import os
from dotenv import load_dotenv

# Lade Umgebungsvariablen aus einer .env-Datei
load_dotenv()

# Passwort-Hashing-Konfiguration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Datenbankverbindung konfigurieren
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
Base = declarative_base()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# FastAPI-App initialisieren
app = FastAPI()

# CORS-Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://zutrittssystemweb.onrender.com"],  # Frontend-Domain
    allow_credentials=True,
    allow_methods=["*"],  # Alle Methoden (GET, POST, etc.)
    allow_headers=["*"],  # Alle Header-Typen
)

# Datenbank-Modelle
class Schueler(Base):
    __tablename__ = 'schueler'
    schueler_id = Column(Integer, primary_key=True, index=True)
    vorname = Column(String, nullable=False)
    nachname = Column(String, nullable=False)
    klasse = Column(String, nullable=False)
    rfid_tag = Column(String, nullable=True)
    zugang = relationship("Zugang", back_populates="schueler")

class Raum(Base):
    __tablename__ = 'raeume'
    raum_id = Column(Integer, primary_key=True, index=True)
    raum_name = Column(String, unique=True, nullable=False)

class Zugang(Base):
    __tablename__ = 'zugang'
    zugang_id = Column(Integer, primary_key=True, index=True)
    schueler_id = Column(Integer, ForeignKey('schueler.schueler_id'))
    raum_id = Column(Integer, ForeignKey('raeume.raum_id'))
    datum = Column(Date, nullable=False)
    zeit_von = Column(Time, nullable=False)  # Zeit von
    zeit_bis = Column(Time, nullable=False)  # Zeit bis
    schueler = relationship("Schueler", back_populates="zugang")
    raum = relationship("Raum")

class RFIDTag(Base):
    __tablename__ = 'rfid_tags'
    tag_id = Column(Integer, primary_key=True, index=True)
    rfid_tag = Column(String, unique=True, nullable=False)

class Benutzer(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)

# Initialisiere die Datenbank
Base.metadata.create_all(bind=engine)

# API-Datenmodelle
class SchuelerRequest(BaseModel):
    vorname: str
    nachname: str
    klasse: str
    rfid_tag: str

class RaumRequest(BaseModel):
    raum_name: str

class ZugangRequest(BaseModel):
    raum_id: int
    datum: str
    zeit: str

class RFIDTagRequest(BaseModel):
    rfid_tag: str

class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

# Hilfsfunktionen
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user_by_username(username: str):
    db = SessionLocal()
    user = db.query(Benutzer).filter(Benutzer.username == username).first()
    db.close()
    return user

@app.post("/login")
def login_user(login_request: LoginRequest):
    user = get_user_by_username(login_request.username)
    if not user or not verify_password(login_request.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Ungültiger Benutzername oder Passwort")

    return {"message": f"Willkommen, {login_request.username}!", "user_id": user.id}

# Beispiel API-Routen
@app.get("/schueler", response_model=List[SchuelerRequest])
def get_schueler():
    db = SessionLocal()
    schueler = db.query(Schueler).all()
    db.close()
    return schueler

@app.post("/schueler")
def add_schueler(schueler: SchuelerRequest):
    db = SessionLocal()
    neuer_schueler = Schueler(
        vorname=schueler.vorname,
        nachname=schueler.nachname,
        klasse=schueler.klasse,
        rfid_tag=schueler.rfid_tag
    )
    db.add(neuer_schueler)
    db.commit()
    db.close()
    return {"message": "Schüler erfolgreich hinzugefügt"}

@app.post("/raeume")
def add_raum(raum: RaumRequest):
    db = SessionLocal()
    neuer_raum = Raum(raum_name=raum.raum_name)
    db.add(neuer_raum)
    db.commit()
    db.close()
    return {"message": "Raum erfolgreich hinzugefügt"}

@app.post("/rfid_tags")
def add_rfid_tag(rfid_tag: RFIDTagRequest):
    db = SessionLocal()
    neuer_tag = RFIDTag(rfid_tag=rfid_tag.rfid_tag)
    db.add(neuer_tag)
    db.commit()
    db.close()
    return {"message": "RFID-Tag erfolgreich hinzugefügt"}
