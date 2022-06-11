from sqlalchemy import Column, DateTime, Integer, String, Boolean, Enum
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from hashlib import sha512
from os import urandom
from binascii import hexlify
import string
import random
import smtplib, ssl

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, autoincrement=True, primary_key=True, index=True)
    username = Column(String(255), unique=True)
    password = Column(String(255), unique=True)
    password_salt = Column(String(255))
    email = Column(String(255), unique=True)
    verified = Column(String(8), default=False, index=True)
    created_at = Column(DateTime, default=datetime.now(), onupdate=datetime.now())

    def veifiedCode(self):
        length = 8
        characters = list(string.ascii_letters + string.digits + "!@#$%^&*()")
        passwordCharacters = [random.choice(characters) for i in range(length)]
        self.verified = "".join(passwordCharacters)
        return f"{self.verified}"


    def generate_salt(self):
        self.password_salt = hexlify(urandom(32)).decode('utf-8').upper()
        return self.password_salt

    def passwordMode(self, password):
        self.generate_salt()
        self.password = self.generate_password_hash(password, self.password_salt)
        return

    def generate_password_hash(self, password, salt):
        return sha512(salt.encode('utf-8') + password.encode('utf-8')).hexdigest().upper()

    def check_password(self, password):
        hash = self.generate_password_hash(password, self.password_salt)
        if hash == self.password:
            return True
        return False