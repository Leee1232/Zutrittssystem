from fastapi import FastAPI, HTTPException
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Date, Time
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from pydantic import BaseModel
from typing import List
import os
from dotenv import load_dotenv

# Lade Umgebungsvariablen aus einer .env-Datei
load_dotenv()

# Datenbankverbindung konfigurieren
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
Base = declarative_base()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# FastAPI-App initialisieren
app = FastAPI()

@app.get("/test")
async def root():
    return {"message": "Hallo, Welt!"}

# Datenbank-Modelle
class Schueler(Base):
    __tablename__ = 'schueler'
    schueler_id = Column(Integer, primary_key=True, index=True)
    vorname = Column(String, nullable=False)
    nachname = Column(String, nullable=False)
    klasse = Column(String, nullable=False)
    rfid_tag = Column(String, nullable=True)  # Optional, da es sein kann, dass nicht jeder Schüler einen RFID-Tag hat
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
    zeit = Column(Time, nullable=False)
    schueler = relationship("Schueler", back_populates="zugang")
    raum = relationship("Raum")

class RFIDTag(Base):
    __tablename__ = 'rfid_tags'
    tag_id = Column(Integer, primary_key=True, index=True)
    rfid_tag = Column(String, unique=True, nullable=False)

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

# API-Routen
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

@app.post("/zugang/{schueler_id}")
def update_zugang(schueler_id: int, zugang: ZugangRequest):
    db = SessionLocal()
    schueler = db.query(Schueler).filter(Schueler.schueler_id == schueler_id).first()
    if not schueler:
        db.close()
        raise HTTPException(status_code=404, detail="Schüler nicht gefunden")

    neuer_zugang = Zugang(
        schueler_id=schueler_id,
        raum_id=zugang.raum_id,
        datum=zugang.datum,
        zeit=zugang.zeit
    )
    db.add(neuer_zugang)
    db.commit()
    db.close()
    return {"message": "Zugang erfolgreich aktualisiert"}

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
        Zugang.zeit == zeit
    ).first()
    db.close()

    if zugang is None:
        return {"message": "Zugang nicht erlaubt"}
    return {"message": "Zugang erlaubt"}
