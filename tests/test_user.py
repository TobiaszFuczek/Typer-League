import pytest
from passlib.hash import bcrypt

from models.user import User


def test_create_user():
    user = User(username="john_doe", email="john@example.com", password_hash="hashed_password")

    assert user.username == "john_doe"
    assert user.email == "john@example.com"
    assert user.password_hash == "hashed_password"


def test_unique_username_and_email():
    user1 = User(username="john_doe", email="john@example.com", password_hash="hashed_password")
    user2 = User(username="jane_smith", email="jane@example.com", password_hash="hashed_password")

    assert user1.username != user2.username
    assert user1.email != user2.email


def test_user_authentication():
    user = User(username="john_doe", email="john@example.com", password_hash="hashed_password")
    assert user.authenticate("password")




def test_input_validation():
    with pytest.raises(ValueError):
        user = User(username="john_doe", email="invalid_email", password_hash="hashed_password")



def test_user_representation():
    user = User(username="john_doe", email="john@example.com", password_hash="hashed_password")

    assert repr(user) == "<User(username=john_doe, email=john@example.com)>"


def test_user_authentication():
    hashed_password = bcrypt.hash("password")  # Generujemy zahaszowane hasło
    user = User(username="john_doe", email="john@example.com", password_hash=hashed_password)
    assert user.authenticate("password")

def test_authenticate_with_correct_password():
    hashed_password = bcrypt.hash("password")  # Generujemy zahaszowane hasło
    user = User(username="john_doe", email="john@example.com", password_hash=hashed_password)
    assert user.authenticate("password")
