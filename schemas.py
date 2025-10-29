from pydantic import BaseModel, EmailStr
from typing import List, Optional

# ------------------ Message Schemas ------------------ #
class MessageBase(BaseModel):
    content: str

class MessageCreate(MessageBase):
    content: str  # associate a new message with a user

class MessageResponse(MessageBase):
    content: str

    class Config:
        orm_mode = True

# ------------------ User Schemas ------------------ #


class UserBase(BaseModel):
    username: str
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    messages: List[MessageResponse] = []
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str
