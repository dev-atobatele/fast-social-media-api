from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from database import Base

class User(Base):
    __tablename__ = "users"

    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

    messages = relationship("Message", back_populates="owner")


class Message(Base):
    __tablename__ = "messages"

    content = Column(String, nullable=False)
    owner = relationship("User", back_populates="messages")
