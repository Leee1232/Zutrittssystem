from sqlalchemy.orm import Session  # Füge diesen Import hinzu
from fastapi import FastAPI, HTTPException, Response, Depends
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Date, Time
from sqlalchemy.orm import registry, sessionmaker, relationship
from dotenv import load_dotenv
import os
from typing import List
from fastapi.middleware.cors import CORSMiddleware  # Importiere CORSMiddleware
from fastapi import HTTPException, status
import bcrypt
from fastapi import HTTPException, status
import redis  # Beispiel für Redis als Datenbank
import jwt
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends
from fastapi import Request
from fastapi import HTTPException, Depends
from fastapi.responses import FileResponse
import os

# Lade Umgebungsvariablen aus der .env Datei
load_dotenv()

# FastAPI-Instanz
app = FastAPI()

# CORS-Konfiguration hinzufügen
origins = [
    "http://localhost:8080",
    "http://localhost:8000",  # Ersetze dies mit der URL, auf der dein Frontend läuft
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Welche Ursprünge sind erlaubt?
    allow_credentials=True,
    allow_methods=["*"],  # Erlaubt alle HTTP-Methoden
    allow_headers=["*"],  # Erlaubt alle Header
)


# SQLAlchemy Setup
mapper_registry = registry()
Base = mapper_registry.generate_base()

# Datenbankverbindung und Session
DATABASE_URL = f"mysql+mysqlconnector://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
engine = create_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# SQLAlchemy-Modelle
class RfidTag(Base):
    __tablename__ = 'rfid_tags'
    tag_id = Column(Integer, primary_key=True, index=True)
    rfid_tag = Column(String(255), unique=True, nullable=False)

class Schueler(Base):
    __tablename__ = 'schueler'
    schueler_id = Column(Integer, primary_key=True, index=True)
    vorname = Column(String(255), nullable=False)
    nachname = Column(String(255), nullable=False)
    klasse = Column(String(255), nullable=False)
    tag_id = Column(Integer, ForeignKey('rfid_tags.tag_id'))
    tag = relationship('RfidTag')

class Raum(Base):
    __tablename__ = 'raeume'
    raum_id = Column(Integer, primary_key=True, index=True)
    raum_name = Column(String(255), unique=True, nullable=False)

class Zugang(Base):
    __tablename__ = 'zugang'
    zugang_id = Column(Integer, primary_key=True, index=True)
    schueler_id = Column(Integer, ForeignKey('schueler.schueler_id'))
    raum_id = Column(Integer, ForeignKey('raeume.raum_id'))
    datum = Column(Date, nullable=False)
    zeit_von = Column(Time, nullable=False)
    zeit_bis = Column(Time, nullable=False)
    schueler = relationship('Schueler')
    raum = relationship('Raum')

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)

# Pydantic-Modelle
class SchuelerRequest(BaseModel):
    vorname: str
    nachname: str
    klasse: str
    tag_id: str

class SchuelerResponse(BaseModel):
    vorname: str
    nachname: str
    klasse: str

    class Config:
        orm_mode = True

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



# Secret Key für das JWT (sollte sicher und zufällig sein)
SECRET_KEY = os.getenv('SECRET_KEY', 'mysecretkey')
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Token-Ablaufzeit in Minuten

# OAuth2PasswordBearer für die Authentifizierung
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
# Hier könnte eine Redis-Verbindung oder eine einfache In-Memory-Blackliste sein
token_blacklist = set()  # Dies ist nur ein einfaches Beispiel

def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)):
    """
    Diese Funktion erstellt das JWT-Token mit einer festgelegten Ablaufzeit (30 Minuten).
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta  # Ablaufzeitpunkt setzen
    to_encode.update({"exp": expire})  # Ablaufzeit in die Nutzdaten einfügen
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)  # JWT codieren
    print(encoded_jwt)
    return encoded_jwt

def verify_access_token(token: str):
    """
    Diese Funktion verifiziert, ob das übergebene Token gültig ist und ob es abgelaufen ist.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])  # Token dekodieren
        print(payload)
        return payload  # Rückgabe der Payload (Benutzername)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token abgelaufen")  # Fehler, wenn Token abgelaufen ist
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Ungültiges Token")  # Fehler bei ungültigem Token

# Funktion zur Extraktion des aktuellen Benutzers
def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Diese Funktion extrahiert den Benutzernamen aus dem Token und verifiziert es.
    """
    payload = verify_access_token(token)  # Überprüfe das Token
    username: str = payload.get("sub")  # Benutzername aus der Payload extrahieren
    if username is None:
        raise HTTPException(status_code=401, detail="Ungültiges Token")  # Fehler, wenn der Benutzername nicht vorhanden ist
    return username  # Benutzername zurückgeben

@app.get("/check_token")
def check_token(current_user: str = Depends(get_current_user)):
    return {"message": "Token gültig"}
    
# Passwort-Hashing und Verifikation
def get_password_hash(password: str) -> str:
    # Hash the password with bcrypt
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    # Verify the password using bcrypt
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# Datenbank-Sessions
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# API-Routen
@app.post("/login")
def login_user(login_request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == login_request.username).first()
    if not user or not verify_password(login_request.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Ungültiger Benutzername oder Passwort")

    # Erstelle das JWT-Token mit einer Ablaufzeit von 30 Minuten
    access_token = create_access_token(data={"sub": user.username})

    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/register")
def register_user(register_request: RegisterRequest, db: Session = Depends(get_db)):
    # Check if username already exists
    existing_user = db.query(User).filter(User.username == register_request.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Benutzername bereits vergeben")
    
    # Hash the password (replace with a secure hashing method like bcrypt in production)
    hashed_password = get_password_hash(register_request.password)
    
    # Create new user
    new_user = User(
        username=register_request.username,
        hashed_password=hashed_password
    )
    
    # Add user to database
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {"message": f"Benutzer {register_request.username} erfolgreich registriert"}

@app.post("/logout")
async def logout_user(request: Request):
    token = request.headers.get("Authorization")  # JWT-Token aus dem Header bekommen
    if token:
        token_blacklist.add(token)  # Token zur Blacklist hinzufügen
        return {"message": "Logout erfolgreich"}
    raise HTTPException(status_code=401, detail="Token fehlt oder ungültig")


@app.post("/schueler")
def add_schueler(schueler: SchuelerRequest, db: Session = Depends(get_db)):
    # First, check if the RFID tag exists
    rfid_tag = db.query(RfidTag).filter(RfidTag.rfid_tag == schueler.tag_id).first()
    
    # If RFID tag doesn't exist, create it
    if not rfid_tag:
        rfid_tag = RfidTag(rfid_tag=schueler.tag_id)
        db.add(rfid_tag)
        db.commit()
        db.refresh(rfid_tag)
    
    # Create new Schueler with the associated RFID tag
    neuer_schueler = Schueler(
        vorname=schueler.vorname,
        nachname=schueler.nachname,
        klasse=schueler.klasse,
        tag_id=rfid_tag.tag_id  # Use the tag_id from the database
    )
    
    # Add and commit the new Schueler
    db.add(neuer_schueler)
    db.commit()
    db.refresh(neuer_schueler)
    
    return {
        "message": "Schüler erfolgreich hinzugefügt",
        "schueler_id": neuer_schueler.schueler_id
    }

@app.get("/schueler", response_model=List[SchuelerResponse])
def get_schueler(db: Session = Depends(get_db)):
    # Fetch Schueler with only vorname, nachname, and klasse
    schueler = db.query(Schueler).all()
    
    # Manually convert to response model to ensure all data is included
    return [
        SchuelerResponse(
            vorname=s.vorname,
            nachname=s.nachname,
            klasse=s.klasse
        ) for s in schueler
    ]

@app.get("/schueler/{schueler_id}", response_model=SchuelerResponse)
def get_schueler_by_id(schueler_id: int, db: Session = Depends(get_db)):
    # Fetch a specific Schueler by ID
    schueler = db.query(Schueler).filter(Schueler.schueler_id == schueler_id).first()
    
    if not schueler:
        raise HTTPException(status_code=404, detail="Schüler nicht gefunden")
    
    return SchuelerResponse(
        vorname=schueler.vorname,
        nachname=schueler.nachname,
        klasse=schueler.klasse
    )

@app.post("/raeume")
def add_raum(raum: RaumRequest, db: Session = Depends(get_db)):
    neuer_raum = Raum(raum_name=raum.raum_name)
    db.add(neuer_raum)
    db.commit()
    return {"message": "Raum erfolgreich hinzugefügt"}

@app.post("/zugang/{schueler_id}")
def update_zugang(schueler_id: int, zugang: ZugangRequest, db: Session = Depends(get_db)):
    schueler = db.query(Schueler).filter(Schueler.schueler_id == schueler_id).first()
    if not schueler:
        raise HTTPException(status_code=404, detail="Schüler nicht gefunden")

    # Prüfen, ob der Schüler bereits Zugang hat
    existing_zugang = db.query(Zugang).filter(
        Zugang.schueler_id == schueler_id,
        Zugang.raum_id == zugang.raum_id,
        Zugang.datum == zugang.datum
    ).first()

    if existing_zugang:
        # Zugang aktualisieren
        existing_zugang.zeit_von = zugang.zeit.split('-')[0]
        existing_zugang.zeit_bis = zugang.zeit.split('-')[1]
        db.commit()
        return {"message": "Zugang erfolgreich aktualisiert"}
    else:
        # Neuen Zugang hinzufügen
        neuer_zugang = Zugang(
            schueler_id=schueler_id,
            raum_id=zugang.raum_id,
            datum=zugang.datum,
            zeit_von=zugang.zeit.split('-')[0],
            zeit_bis=zugang.zeit.split('-')[1]
        )
        db.add(neuer_zugang)
        db.commit()
        return {"message": "Neuer Zugang erfolgreich hinzugefügt"}

@app.post("/rfid_tags")
def add_rfid_tag(rfid_tag: RFIDTagRequest, db: Session = Depends(get_db)):
    neuer_tag = RfidTag(rfid_tag=rfid_tag.rfid_tag)
    db.add(neuer_tag)
    db.commit()
    return {"message": "RFID-Tag erfolgreich hinzugefügt"}

@app.get("/check_zugang/{rfid_tag}/{raum_id}/{datum}/{zeit}")
def check_zugang(rfid_tag: str, raum_id: int, datum: str, zeit: str, db: Session = Depends(get_db)):
    schueler = db.query(Schueler).filter(Schueler.rfid_tag == rfid_tag).first()
    if not schueler:
        raise HTTPException(status_code=404, detail="Schüler nicht gefunden")

    zugang = db.query(Zugang).filter(
        Zugang.schueler_id == schueler.schueler_id,
        Zugang.raum_id == raum_id,
        Zugang.datum == datum,
        Zugang.zeit_von <= zeit,
        Zugang.zeit_bis >= zeit
    ).first()

    if zugang is None:
        return {"message": "Zugang nicht erlaubt"}
    return {"message": "Zugang erlaubt"}

# Wenn du die Tabellen noch nicht erstellt hast, kannst du dies hier tun:
Base.metadata.create_all(bind=engine)
