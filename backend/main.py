from sqlalchemy.orm import Session  # Füge diesen Import hinzu
from fastapi import FastAPI, HTTPException, Response, Depends
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Date, Time
from sqlalchemy.orm import registry, sessionmaker, relationship
from dotenv import load_dotenv
import os
from typing import List

# Lade Umgebungsvariablen aus der .env Datei
load_dotenv()

# FastAPI-Instanz
app = FastAPI()

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

class LoginRequest(BaseModel):
    username: str
    password: str

# Hilfsfunktionen
def get_password_hash(password):
    return password  # Beispiel: Ersetze mit einem echten Hashing-Algorithmus wie bcrypt

def verify_password(plain_password, hashed_password):
    return plain_password == hashed_password  # Beispiel: Ersetze mit einem echten Vergleich

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
    return {"message": f"Willkommen zurück, {login_request.username}!"}

@app.post("/schueler")
def add_schueler(schueler: SchuelerRequest, db: Session = Depends(get_db)):
    neuer_schueler = Schueler(
        vorname=schueler.vorname,
        nachname=schueler.nachname,
        klasse=schueler.klasse,
        tag_id=schueler.tag_id
    )
    db.add(neuer_schueler)
    db.commit()
    return {"message": "Schüler erfolgreich hinzugefügt"}

@app.get("/schueler", response_model=List[SchuelerResponse])
def get_schueler(db: Session = Depends(get_db)):
    schueler = db.query(Schueler).all()
    return schueler

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
