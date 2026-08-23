import os
from sqlalchemy import create_engine, Column, Integer, String, Text, Float, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

os.makedirs("data", exist_ok=True)
SQLALCHEMY_DATABASE_URL = "sqlite:///data/aeroguard.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class DBIncidentLog(Base):
    __tablename__ = "incident_logs"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(Text)
    bssid = Column(String, index=True)
    score = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)

class DBBaseline(Base):
    __tablename__ = "baselines"
    id = Column(Integer, primary_key=True, index=True)
    ssid = Column(String, unique=True, index=True)
    json_data = Column(Text) # Store the serialized JSON of the SSIDProfile

Base.metadata.create_all(bind=engine)
