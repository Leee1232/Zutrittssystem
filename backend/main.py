from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Date, Time
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from pydantic import BaseModel
from passlib.context import CryptContext
from typing import List
import os
import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer

# Lade Umgebungsvariablen aus einer .env-Datei
load_dotenv()

# Passwort-Hashing-Konfiguration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT-Konfiguration
SECRET_KEY = os.getenv("SECRET_KEY", "mysecretkey")  # Dein geheimer Schlüssel für JWT
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Token läuft nach 30 Minuten ab

# Datenbankverbindung konfigurieren
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
Base = declarative_base()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# FastAPI-App initialisieren
app = FastAPI()

# CORS-Konfiguration hinzufügen
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Erlaubt alle Ursprünge (kann auf bestimmte Ursprünge gesetzt werden)
    allow_credentials=True,
    allow_methods=["*"],  # Erlaubt alle HTTP-Methoden wie GET, POST, etc.
    allow_headers=["*"],  # Erlaubt alle Header
)

# OAuth2PasswordBearer ist für die Verwendung des Tokens als Bearer Token im Header gedacht
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Hilfsfunktionen zur Erstellung und Verifizierung von JWTs
def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token or expired token")

# Hilfsfunktionen für Benutzer
def get_user_by_username(username: str):
    db = SessionLocal()
    user = db.query(Benutzer).filter(Benutzer.username == username).first()
    db.close()
    return user

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# API-Datenmodelle
class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

# Benutzer-Modell für die Authentifizierung
class User(BaseModel):
    username: str

# Funktion, um den aktuell authentifizierten Benutzer abzurufen
def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    user = payload.get("sub")
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    return user

# Datenbank-Modelle (wie du sie bereits hast)
class Schueler(Base):
    __tablename__ = 'schueler'
    schueler_id = Column(Integer, primary_key=True, index=True)
    vorname = Column(String, nullable=False)
    nachname = Column(String, nullable=False)
    klasse = Column(String, nullable=False)
    tag_id = Column(String, nullable=True)  # Hier anpassen
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
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)

# Initialisiere die Datenbank
Base.metadata.create_all(bind=engine)

# Hilfsfunktionen
def get_password_hash(password):
    return pwd_context.hash(password)

@app.post("/login")
def login_user(login_request: LoginRequest):
    user = get_user_by_username(login_request.username)
    if not user or not verify_password(login_request.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Ungültiger Benutzername oder Passwort")
    
    # Erstelle das JWT für den authentifizierten Benutzer
    access_token = create_access_token(data={"sub": login_request.username})
    return {"access_token": access_token, "token_type": "bearer"}

# Beispiel API-Routen (Schüler, Räume, RFID-Logik wie oben beschrieben)
@app.get("/schueler", response_model=List[SchuelerResponse])
def get_schueler(current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    schueler = db.query(Schueler).all()
    db.close()
    return schueler

@app.post("/schueler")
def add_schueler(schueler: SchuelerRequest, current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    neuer_schueler = Schueler(
        vorname=schueler.vorname,
        nachname=schueler.nachname,
        klasse=schueler.klasse,
        tag_id=schueler.tag_id
    )
    db.add(neuer_schueler)
    db.commit()
    db.close()
    return {"message": "Schüler erfolgreich hinzugefügt"}

@app.post("/raeume")
def add_raum(raum: RaumRequest, current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    neuer_raum = Raum(raum_name=raum.raum_name)
    db.add(neuer_raum)
    db.commit()
    db.close()
    return {"message": "Raum erfolgreich hinzugefügt"}

@app.post("/zugang/{schueler_id}")
def update_zugang(schueler_id: int, zugang: ZugangRequest, current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    schueler = db.query(Schueler).filter(Schueler.schueler_id == schueler_id).first()
    if not schueler:
        db.close()
        raise HTTPException(status_code=404, detail="Schüler nicht gefunden")

    # Prüfen, ob der Schüler bereits Zugang zu diesem Raum und Datum hat
    existing_zugang = db.query(Zugang).filter(
        Zugang.schueler_id == schueler_id,
        Zugang.raum_id == zugang.raum_id,
        Zugang.datum == zugang.datum
    ).first()

    if existing_zugang:
        # Falls ein Zugang existiert, aktualisieren wir die Zeiten
        existing_zugang.zeit_von = zugang.zeit.split('-')[0]
        existing_zugang.zeit_bis = zugang.zeit.split('-')[1]
        db.commit()
        db.close()
        return {"message": "Zugang erfolgreich aktualisiert"}
    else:
        # Falls kein Zugang existiert, fügen wir einen neuen Zugang hinzu
        neuer_zugang = Zugang(
            schueler_id=schueler_id,
            raum_id=zugang.raum_id,
            datum=zugang.datum,
            zeit_von=zugang.zeit.split('-')[0],  # Zeit von
            zeit_bis=zugang.zeit.split('-')[1]   # Zeit bis
        )
        db.add(neuer_zugang)
        db.commit()
        db.close()
        return {"message": "Neuer Zugang erfolgreich hinzugefügt"}

@app.post("/rfid_tags")
def add_rfid_tag(rfid_tag: RFIDTagRequest, current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    neuer_tag = RFIDTag(rfid_tag=rfid_tag.rfid_tag)
    db.add(neuer_tag)
    db.commit()
    db.close()
    return {"message": "RFID-Tag erfolgreich hinzugefügt"}

@app.get("/check_zugang/{rfid_tag}/{raum_id}/{datum}/{zeit}")
def check_zugang(rfid_tag: str, raum_id: int, datum: str, zeit: str, current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    schueler = db.query(Schueler).filter(Schueler.rfid_tag == rfid_tag).first()
    if not schueler:
        db.close()
        raise HTTPException(status_code=404, detail="Schüler nicht gefunden")

    zugang = db.query(Zugang).filter(
        Zugang.schueler_id == schueler.schueler_id,
        Zugang.raum_id == raum_id,
        Zugang.datum == datum,
        Zugang.zeit_von <= zeit,
        Zugang.zeit_bis >= zeit
    ).first()

    db.close()

    if zugang is None:
        return {"message": "Zugang nicht erlaubt"}
    return {"message": "Zugang erlaubt"}
