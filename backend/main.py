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
from logger import logger  # Importiere den Logger aus der logger.py Datei


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

class Klasse(Base):
    __tablename__ = 'klassen'
    klasse_id = Column(Integer, primary_key=True, index=True)
    klasse_name = Column(String(255), unique=True, nullable=False)

# Pydantic-Modelle
class SchuelerRequest(BaseModel):
    vorname: str
    nachname: str
    klasse: str
    tag_id: str

class SchuelerResponse(BaseModel):
    schueler_id: int
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

class KlasseRequest(BaseModel):
    klasse_name: str

# Secret Key für das JWT (sollte sicher und zufällig sein)
SECRET_KEY = os.getenv('SECRET_KEY', 'mysecretkey')
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # Token-Ablaufzeit in Minuten (8 Stunden)

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
    logger.info(f"Token erstellt: {encoded_jwt}")
    return encoded_jwt

def verify_access_token(token: str):
    """
    Diese Funktion verifiziert, ob das übergebene Token gültig ist und ob es abgelaufen ist.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])  # Token dekodieren
        print(payload)
        logger.info(f"Token verifiziert: {payload}")
        return payload  # Rückgabe der Payload (Benutzername)
    except jwt.ExpiredSignatureError:
        logger.warning("Token abgelaufen")
        raise HTTPException(status_code=401, detail="Token abgelaufen")  # Fehler, wenn Token abgelaufen ist
    except jwt.JWTError:
        logger.error("Ungültiges Token")
        raise HTTPException(status_code=401, detail="Ungültiges Token")  # Fehler bei ungültigem Token

# Funktion zur Extraktion des aktuellen Benutzers
def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Diese Funktion extrahiert den Benutzernamen aus dem Token und verifiziert es.
    """
    payload = verify_access_token(token)  # Überprüfe das Token
    username: str = payload.get("sub")  # Benutzername aus der Payload extrahieren
    if username is None:
        logger.error("Benutzername fehlt im Token")
        raise HTTPException(status_code=401, detail="Ungültiges Token")  # Fehler, wenn der Benutzername nicht vorhanden ist
    return username  # Benutzername zurückgeben

@app.get("/check_token")
def check_token(current_user: str = Depends(get_current_user)):
    logger.info(f"Token von {current_user} ist gültig.")
    logger.info(f"Vollständige Benutzer-Informationen: {current_user}")
    return {"message": "Token gültig", "username": current_user}
    
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
        logger.warning(f"Login fehlgeschlagen für Benutzer {login_request.username}")
        raise HTTPException(status_code=401, detail="Ungültiger Benutzername oder Passwort")

    # Erstelle das JWT-Token mit einer Ablaufzeit von 30 Minuten
    access_token = create_access_token(data={"sub": user.username})
    logger.info(f"Benutzer {user.username} hat sich erfolgreich eingeloggt.")
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/register")
def register_user(register_request: RegisterRequest, db: Session = Depends(get_db)):
    # Check if username already exists
    existing_user = db.query(User).filter(User.username == register_request.username).first()
    if existing_user:
        logger.warning(f"Benutzername {register_request.username} bereits vergeben.")
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
    logger.info(f"Neuer Benutzer {register_request.username} erfolgreich registriert.")
    return {"message": f"Benutzer {register_request.username} erfolgreich registriert"}

@app.post("/logout")
async def logout_user(request: Request):
    token = request.headers.get("Authorization")  # JWT-Token aus dem Header bekommen
    if token:
        token_blacklist.add(token)  # Token zur Blacklist hinzufügen
        logger.info("Logout erfolgreich.")
        return {"message": "Logout erfolgreich"}
    logger.warning("Token fehlt oder ungültig")
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
        logger.info(f"RFID-Tag {schueler.tag_id} erstellt.")

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
    logger.info(f"Schüler {schueler.vorname} {schueler.nachname} erfolgreich hinzugefügt.")
    return {
        "message": "Schüler erfolgreich hinzugefügt",
        "schueler_id": neuer_schueler.schueler_id
    }

@app.get("/schueler", response_model=List[SchuelerResponse])
def get_schueler(db: Session = Depends(get_db)):
    # Fetch Schueler with only vorname, nachname, and klasse
    schueler = db.query(Schueler).all()
    logger.info("Alle Schüler abgerufen.")

    # Manually convert to response model to ensure all data is included
    return [
        SchuelerResponse(
            schueler_id=s.schueler_id,
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
        logger.warning(f"Schüler mit ID {schueler_id} nicht gefunden.")
        raise HTTPException(status_code=404, detail="Schüler nicht gefunden")
    
    return SchuelerResponse(
        schueler_id=schueler.schueler_id,
        vorname=schueler.vorname,
        nachname=schueler.nachname,
        klasse=schueler.klasse
    )

@app.post("/raeume")
def add_raum(raum: RaumRequest, db: Session = Depends(get_db)):
    neuer_raum = Raum(raum_name=raum.raum_name)
    db.add(neuer_raum)
    db.commit()
    logger.info(f"Raum {raum.raum_name} erfolgreich hinzugefügt.")
    return {"message": "Raum erfolgreich hinzugefügt"}

@app.post("/zugang/{schueler_id}")
def update_zugang(schueler_id: int, zugang: ZugangRequest, db: Session = Depends(get_db)):
    schueler = db.query(Schueler).filter(Schueler.schueler_id == schueler_id).first()
    if not schueler:
        logger.warning(f"Schüler mit ID {schueler_id} nicht gefunden.")
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
        logger.info(f"Zugang für Schüler {schueler_id} erfolgreich aktualisiert.")
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
        logger.info(f"Neuer Zugang für Schüler {schueler_id} hinzugefügt.")
        return {"message": "Neuer Zugang erfolgreich hinzugefügt"}

@app.post("/rfid_tags")
def add_rfid_tag(rfid_tag: RFIDTagRequest, db: Session = Depends(get_db)):
    neuer_tag = RfidTag(rfid_tag=rfid_tag.rfid_tag)
    db.add(neuer_tag)
    db.commit()
    logger.info(f"RFID-Tag {rfid_tag.rfid_tag} erfolgreich hinzugefügt.")
    return {"message": "RFID-Tag erfolgreich hinzugefügt"}

@app.get("/check_zugang/{rfid_tag}/{raum_id}/{datum}/{zeit}")
def check_zugang(rfid_tag: str, raum_id: int, datum: str, zeit: str, db: Session = Depends(get_db)):
    # Debuggen der Eingabeparameter
    logger.info(f"Check Zugang - RFID-Tag: {rfid_tag}, Raum-ID: {raum_id}, Datum: {datum}, Zeit: {zeit}")

    # Schüler über RFID-Tag mit Join suchen
    schueler = db.query(Schueler).join(RfidTag, Schueler.tag_id == RfidTag.tag_id).filter(RfidTag.rfid_tag == rfid_tag).first()
    
    if not schueler:
        logger.warning(f"Schüler mit RFID-Tag {rfid_tag} nicht gefunden.")
        raise HTTPException(status_code=404, detail="Schüler nicht gefunden")

    logger.info(f"Gefundener Schüler: {schueler.vorname} {schueler.nachname}")

    # Zugang überprüfen
    zugang = db.query(Zugang).filter(
        Zugang.schueler_id == schueler.schueler_id,
        Zugang.raum_id == raum_id,
        Zugang.datum == datum,
        Zugang.zeit_von <= zeit,
        Zugang.zeit_bis >= zeit
    ).first()

    if zugang is None:
        logger.info(f"Kein Zugang für Schüler {schueler.schueler_id} im Raum {raum_id} zur Zeit {zeit}")
        return {"message": "Zugang nicht erlaubt"}
    
    logger.info(f"Zugang für Schüler {schueler.schueler_id} erlaubt")
    return {"message": "Zugang erlaubt"}

@app.get("/raeume", response_model=List[RaumRequest])
def get_raeume(db: Session = Depends(get_db)):
    """
    Ruft alle Räume aus der Datenbank ab.
    
    :param db: Datenbankverbindung
    :return: Liste aller Räume
    """
    try:
        raeume = db.query(Raum).all()
        return [{"raum_name": raum.raum_name} for raum in raeume]
    except Exception as e:
        logger.error(f"Fehler beim Abrufen der Räume: {e}")
        raise HTTPException(status_code=500, detail="Fehler beim Abrufen der Räume")

@app.get("/schueler", response_model=List[SchuelerResponse])
def get_alle_schueler(db: Session = Depends(get_db)):
    """
    Ruft alle Schüler aus der Datenbank ab.
    
    :param db: Datenbankverbindung
    :return: Liste aller Schüler
    """
    try:
        schueler = db.query(Schueler).all()
        return [
            {
                "schueler_id": s.schueler_id,
                "vorname": s.vorname,
                "nachname": s.nachname,
                "klasse": s.klasse
            } for s in schueler
        ]
    except Exception as e:
        logger.error(f"Fehler beim Abrufen der Schüler: {e}")
        raise HTTPException(status_code=500, detail="Fehler beim Abrufen der Schüler")

@app.post("/klassen")
def add_klasse(klasse: KlasseRequest, db: Session = Depends(get_db)):
    """
    Fügt eine neue Klasse zur Datenbank hinzu.
    
    :param klasse: Klasse-Objekt mit Klassenname
    :param db: Datenbankverbindung
    :return: Erfolgsmeldung
    """
    try:
        # Überprüfen, ob Klasse bereits existiert
        existing_klasse = db.query(Klasse).filter(Klasse.klasse_name == klasse.klasse_name).first()
        if existing_klasse:
            logger.warning(f"Klasse {klasse.klasse_name} existiert bereits.")
            raise HTTPException(status_code=400, detail="Klasse existiert bereits")

        neue_klasse = Klasse(klasse_name=klasse.klasse_name)
        db.add(neue_klasse)
        db.commit()
        db.refresh(neue_klasse)
        logger.info(f"Klasse {klasse.klasse_name} erfolgreich hinzugefügt.")
        return {"message": "Klasse erfolgreich hinzugefügt"}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Fehler beim Hinzufügen der Klasse: {e}")
        raise HTTPException(status_code=500, detail="Fehler beim Hinzufügen der Klasse")

@app.get("/klassen", response_model=List[KlasseRequest])
def get_klassen(db: Session = Depends(get_db)):
    """
    Ruft alle Klassen aus der Datenbank ab.
    
    :param db: Datenbankverbindung
    :return: Liste aller Klassen
    """
    try:
        klassen = db.query(Klasse).all()
        return [{"klasse_name": klasse.klasse_name} for klasse in klassen]
    except Exception as e:
        logger.error(f"Fehler beim Abrufen der Klassen: {e}")
        raise HTTPException(status_code=500, detail="Fehler beim Abrufen der Klassen")

# Wenn du die Tabellen noch nicht erstellt hast, kannst du dies hier tun:
Base.metadata.create_all(bind=engine)
