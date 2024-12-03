from fastapi import FastAPI, HTTPException, Request, Depends
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.orm import relationship
from pydantic import BaseModel
from typing import List, Optional
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

@app.get("/")
async def root():
    return {"message": "Hello, World!"}

# Datenbank-Modelle definieren
class Student(Base):
    __tablename__ = 'students'
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, index=True)
    last_name = Column(String, index=True)
    class_name = Column(String, index=True)
    room_access = relationship("RoomAccess", back_populates="student")

class RoomAccess(Base):
    __tablename__ = 'room_access'
    id = Column(Integer, primary_key=True, index=True)
    student_id = Column(Integer, ForeignKey('students.id'))
    room_name = Column(String, index=True)
    is_allowed = Column(Integer)  # 1 für erlaubt, 0 für gesperrt
    student = relationship("Student", back_populates="room_access")

# Initialisiere die Datenbank (einmalig ausführen)
Base.metadata.create_all(bind=engine)

# API-Datenmodelle
class StudentRequest(BaseModel):
    first_name: str
    last_name: str
    class_name: str

class RoomAccessRequest(BaseModel):
    room_name: str
    is_allowed: int

# Routen für das API
@app.get("/students", response_model=List[StudentRequest])
def get_students():
    """Gibt eine Liste aller Schüler zurück"""
    db = SessionLocal()
    students = db.query(Student).all()
    db.close()
    return students

@app.get("/student/{student_id}")
def get_student(student_id: int):
    """Gibt die Details eines bestimmten Schülers zurück"""
    db = SessionLocal()
    student = db.query(Student).filter(Student.id == student_id).first()
    db.close()
    if student is None:
        raise HTTPException(status_code=404, detail="Student not found")
    return student

@app.post("/update_access/{student_id}")
def update_room_access(student_id: int, room_access: RoomAccessRequest):
    """Aktualisiert den Zutritt eines Schülers zu einem bestimmten Raum"""
    db = SessionLocal()
    student = db.query(Student).filter(Student.id == student_id).first()
    if not student:
        db.close()
        raise HTTPException(status_code=404, detail="Student not found")
    
    # Prüfen, ob der Eintrag für den Raum existiert
    access = db.query(RoomAccess).filter(
        RoomAccess.student_id == student_id, RoomAccess.room_name == room_access.room_name
    ).first()

    if access:
        # Bestehenden Zutritt aktualisieren
        access.is_allowed = room_access.is_allowed
    else:
        # Neuen Zutritt anlegen
        new_access = RoomAccess(student_id=student_id, room_name=room_access.room_name, is_allowed=room_access.is_allowed)
        db.add(new_access)

    db.commit()
    db.close()
    return {"message": "Room access updated successfully"}

@app.get("/check_access/{student_id}/{room_name}")
def check_room_access(student_id: int, room_name: str):
    """Überprüft, ob ein Schüler Zutritt zu einem Raum hat"""
    db = SessionLocal()
    access = db.query(RoomAccess).filter(
        RoomAccess.student_id == student_id, RoomAccess.room_name == room_name
    ).first()
    db.close()
    
    if access is None:
        raise HTTPException(status_code=404, detail="Access information not found")
    
    if access.is_allowed == 1:
        return {"message": "Access granted"}
    else:
        return {"message": "Access denied"}
