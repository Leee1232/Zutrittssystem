from fastapi import FastAPI, HTTPException, Response
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Date, Time
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from pydantic import BaseModel
from passlib.context import CryptContext
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

from fastapi.middleware.cors import CORSMiddleware
# CORS-Konfiguration hinzufügen
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Erlaubt alle Ursprünge (kann auf bestimmte Ursprünge gesetzt werden)
    allow_credentials=True,
    allow_methods=["*"],  # Erlaubt alle HTTP-Methoden wie GET, POST, etc.
    allow_headers=["*"],  # Erlaubt alle Header
)

@app.get("/")
async def root():
    return {"message": "Api geht"}

# Datenbank-Modelle
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

# API-Datenmodelle
class SchuelerRequest(BaseModel):
    vorname: str
    nachname: str
    klasse: str
    tag_id: str  # Hier anpassen

class SchuelerResponse(BaseModel):
    schueler_id: int
    vorname: str
    nachname: str
    klasse: str
    tag_id: str

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

# API-Datenmodelle
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

# Login-API
@app.post("/login")
def login_user(login_request: LoginRequest):
    user = get_user_by_username(login_request.username)
    if not user or not verify_password(login_request.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Ungültiger Benutzername oder Passwort")

    # Hier könnte ein JWT Token erzeugt und zurückgegeben werden
    return {"message": f"Willkommen zurück, {login_request.username}!"}

# Logout-API
@app.post("/logout")
def logout_user(response: Response):
    # Hier könntest du den Token löschen oder ungültig machen, falls du Token verwendest.
    # Wenn du Cookies verwendest, kannst du sie hier löschen:
    response.delete_cookie(key="access_token")  # Falls du Cookies nutzt
    return {"message": "Erfolgreich abgemeldet"}

# Beispiel API-Routen (Schüler, Räume, RFID-Logik wie oben beschrieben)
@app.get("/schueler", response_model=List[SchuelerResponse])
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
        tag_id=schueler.tag_id
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

@app.post("/zugang/{schueler_id}")
def update_zugang(schueler_id: int, zugang: ZugangRequest):
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
def add_rfid_tag(rfid_tag: RFIDTagRequest):
    db = SessionLocal()
    neuer_tag = RFIDTag(rfid_tag=rfid_tag.rfid_tag)
    db.add(neuer_tag)
    db.commit()
    db.close()
    return {"message": "RFID-Tag erfolgreich hinzugefügt"}

@app.get("/check_zugang/{rfid_tag}/{raum_id}/{datum}/{zeit}")
def check_zugang(rfid_tag: str, raum_id: int, datum: str, zeit: str):
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