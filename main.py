from typing import List
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta
from database import Base, engine
from models import User, Message
from schemas import UserCreate, UserResponse, MessageCreate, MessageResponse, Token, MessageBase
from auth import (
    get_db, get_password_hash, verify_password,
    create_access_token, get_current_user,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)

app = FastAPI(title="Social Media API (Auth)", version="1.3")
Base.metadata.create_all(bind=engine)
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# --- Registration ---
@app.post("/api/users", response_model=UserResponse)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed = get_password_hash(user.password)
    db_user = User(username=user.username, email=user.email, hashed_password=hashed)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# --- Login (JWT token) ---
@app.post("/api/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

# --- Protected endpoint (example: send message) ---
@app.post("/api/messages", response_model=MessageResponse)
def create_message(
    payload: MessageCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    db_msg = Message(content=payload.content, user_id=current_user.id)
    db.add(db_msg)
    db.commit()
    db.refresh(db_msg)
    return db_msg

# ... keep GET/DELETE endpoints from before ...
@app.get("/api/messages", response_model=List[MessageResponse])
def get_messages(
    db: Session = Depends(get_db)
):
    """Return all messages."""
    messages = db.query(Message).all()
    return messages

@app.get("/api/users/me", response_model=UserResponse)
def get_current_user_info(current_user=Depends(get_current_user)):
    return current_user

@app.delete("/api/messages/{message_id}")
def delete_message(
    message_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    message = db.query(Message).filter(Message.id == message_id).first()
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    if message.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this message")

    db.delete(message)
    db.commit()
    return {"deleted_message_id": message_id}

@app.put("/api/messages/{message_id}", response_model=MessageResponse)
def update_message(
    message_id: int,
    message_update: MessageBase,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    message = db.query(Message).filter(Message.id == message_id).first()
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    if message.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to update this message")

    message.content = message_update.content
    db.commit()
    db.refresh(message)
    return message
