from sqlalchemy import Column, Integer, String
from .database import Base
from passlib.context import CryptContext
import re

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    is_admin = Column(Boolean, default=False)

    def __repr__(self):
        return f"<User(username={self.username}, email={self.email})>"

    def authenticate(self, password: str) -> bool:
        return pwd_context.verify(password, self.password_hash)

    def __init__(self, username: str, email: str, password_hash: str, is_admin: bool):
        self.username = username
        self.email = self.validate_email(email)
        self.password_hash = password_hash
        self.is_admin = is_admin

    def validate_email(self, email: str) -> str:
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            raise ValueError("Invalid email address")
        return email

    @classmethod
    def create_admin(cls, username: str, email: str, password: str):
        return cls(username=username, email=email, password=password, is_admin=True)