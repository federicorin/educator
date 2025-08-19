from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy import Text, JSON
from werkzeug.security import generate_password_hash, check_password_hash
db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "user"
    id          = db.Column(db.Integer, primary_key=True)
    first_name  = db.Column(db.String(100), nullable=False)
    last_name   = db.Column(db.String(100), nullable=False)
    email       = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role        = db.Column(db.String(50), nullable=False)
    customize_ai = db.Column(Text, nullable=True)
    sessions    = db.relationship("ChatSession", back_populates="user", cascade="all, delete")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class InviteToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    token = db.Column(db.String(64), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)

    def is_valid(self):
        return datetime.utcnow() < self.expires_at

class ChatSession(db.Model):
    __tablename__ = "chat_session"
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(150), default="Nueva sesión")
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at  = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id     = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    # Relaciones
    user        = db.relationship("User", back_populates="sessions")
    messages    = db.relationship("ChatMessage", back_populates="session", cascade="all, delete")
    files       = db.relationship("File",        back_populates="session", cascade="all, delete")

class ChatMessage(db.Model):
    __tablename__ = "chat_message"
    id          = db.Column(db.Integer, primary_key=True)
    session_id  = db.Column(db.Integer, db.ForeignKey("chat_session.id"), nullable=False)
    sender      = db.Column(db.String(20), nullable=False)   # "user" o "assistant"
    text        = db.Column(db.Text,      nullable=False)
    timestamp   = db.Column(db.DateTime,  default=datetime.utcnow)
    audio_path  = db.Column(db.String(512))  # NUEVO: ruta del archivo de audio
    thought_process = db.Column(db.Text, nullable=True)  # nueva columna

    # Relación inversa
    session     = db.relationship("ChatSession", back_populates="messages")

class File(db.Model):
    __tablename__ = "file"
    id          = db.Column(db.Integer, primary_key=True)
    session_id  = db.Column(db.Integer, db.ForeignKey("chat_session.id"), nullable=False)
    user_id     = db.Column(db.Integer, db.ForeignKey("user.id"),         nullable=False)
    filename    = db.Column(db.String(255), nullable=False)
    filepath    = db.Column(db.String(500), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Relaciones inversas
    session     = db.relationship("ChatSession", back_populates="files")
    user        = db.relationship("User")