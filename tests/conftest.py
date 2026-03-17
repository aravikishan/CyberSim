"""Pytest fixtures for CyberSim tests."""

import os
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config
config.TESTING = True

from models.database import Base, get_db
from app import app


TEST_DB_URL = "sqlite:///./test_cybersim.db"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestSession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(autouse=True)
def setup_database():
    """Create tables before each test, drop after."""
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    if os.path.exists("./test_cybersim.db"):
        os.remove("./test_cybersim.db")


@pytest.fixture()
def client():
    """FastAPI test client."""
    return TestClient(app)


@pytest.fixture()
def db_session():
    """Direct DB session for testing models."""
    db = TestSession()
    try:
        yield db
    finally:
        db.close()
