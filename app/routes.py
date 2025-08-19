import os
import re
import json
from flask import Blueprint, request, session as login_session, redirect, url_for, render_template, flash, jsonify, current_app, send_from_directory, session, Response, stream_with_context, request, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from .models import db, User, ChatSession, ChatMessage, File
from werkzeug.security import generate_password_hash
from app.file_reader import procesar_archivo
import uuid
import edge_tts, asyncio
from dotenv import load_dotenv
import threading
import signal
from datetime import datetime

class ThinkStripper:
    """Streaming-safe stripper that removes everything between <think>...</think>,
    including if the tags are split across chunks. Use `.feed(chunk)` to process
    streaming chunks and `.finalize()` at the end to clear any open buffer.
    """
    def __init__(self):
        self._buffer = ''

    def feed(self, s: str) -> str:
        data = self._buffer + (s or '')
        out_parts = []
        pos = 0
        while True:
            m_open = re.search(r'(?i)<think>', data[pos:])
            if not m_open:
                out_parts.append(data[pos:])
                self._buffer = ''
                break
            open_start = pos + m_open.start()
            out_parts.append(data[pos:open_start])
            after_open = open_start + len(m_open.group())
            m_close = re.search(r'(?i)</think>', data[after_open:])
            if m_close:
                close_end = after_open + m_close.end()
                pos = close_end
                continue
            else:
                # No closing tag in this chunk; store from open_start onwards
                self._buffer = data[open_start:]
                break
        return ''.join(out_parts)

    def finalize(self) -> str:
        # Discard any leftover open <think>... (we don't return it)
        self._buffer = ''
        return ''

def strip_think_all(text: str) -> str:
    """Remove all <think>...</think> blocks from a complete text."""
    if not text:
        return text
    return re.sub(r'(?is)<think>.*?</think>', '', text).strip()

# End ThinkStripper / strip_think_all

import secrets
from datetime import timedelta
from .models import InviteToken
from .utils import send_invitation_email
from flask import Response, stream_with_context
from datetime import datetime
import json
import threading
from datetime import datetime
import time
import logging
from typing import Generator
from app.knowledge_base import KnowledgeBase
from app.ollama_stream import ollama_run_for_kb
load_dotenv()
routes = Blueprint('routes', __name__)
bp = Blueprint("chat", __name__)
logger = logging.getLogger(__name__)


def _sanitize_persist(text: str) -> str:
    """
    Sanitiza el texto antes de persistirlo.
    Limpia caracteres problemáticos y limita longitud.
    """
    if not text:
        return ""
    
    # Limitar longitud máxima
    if len(text) > 10000:
        text = text[:10000] + "..."
    
    # Limpiar caracteres problemáticos
    text = text.replace('\x00', '')  # Caracteres nulos
    text = text.strip()
    
    return text

def _sse_json_event(data: dict) -> str:
    """
    Formatea datos como evento Server-Sent Event en formato JSON.
    """
    import json
    try:
        json_str = json.dumps(data, ensure_ascii=False)
        return f"data: {json_str}\n\n"
    except Exception as e:
        logger.error(f"Error formatting SSE event: {e}")
        return "data: {\"error\": \"Failed to format response\"}\n\n"
    
ALLOWED_EXTENSIONS = {
    # Documentos
    'pdf', 'txt', 'doc', 'docx', 'odt',
    
    # Imágenes
    'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp',
    
    # Presentaciones
    'ppt', 'pptx', 'odp',
    
    # Video
    'mp4', 'avi', 'mov', 'mkv', 'wmv', 'webm',
    
    # Audio
    'mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a',
    
    # Archivos comprimidos
    'zip', 'rar', '7z',
    
    # Otros textos
    'md', 'csv', 'json',
}

def create_admin_user():
    admin_email = os.getenv("ADMIN_EMAIL")
    admin_password = os.getenv("ADMIN_PASSWORD")

    if not admin_email or not admin_password:
        print("ADMIN_EMAIL o ADMIN_PASSWORD no están definidos en .env")
        return

    existing_admin = User.query.filter_by(email=admin_email).first()
    if not existing_admin:
        hashed_password = generate_password_hash(admin_password)
        admin_user = User(
            first_name="Admin",
            last_name="Principal",
            email=admin_email,
            password_hash=hashed_password,
            role="admin"
        )
        db.session.add(admin_user)
        db.session.commit()
        print("✅ Usuario administrador creado")
    else:
        print("ℹ️ Usuario administrador ya existe")

def is_admin(user):
    return user.role == 'admin'

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def limpiar_output(texto):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    limpio = ansi_escape.sub('', texto)
    spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    limpio = ''.join(c for c in limpio if c not in spinner_chars)
    limpio = re.sub(r'\n{3,}', '\n\n', limpio)
    return limpio.strip()

@routes.context_processor
def inject_user_globals():
    if 'user_id' in login_session:
        user = User.query.get(login_session['user_id'])
        sessions = ChatSession.query\
                    .filter_by(user_id=user.id)\
                    .order_by(ChatSession.updated_at.desc())\
                    .all()
        return {
            'sessions': sessions,
            'user_name': user.first_name
        }
    return {}

# Obtener las variables de entorno
AI_NAME = os.getenv("AI_NAME")
AI_INSTITUTION = os.getenv("AI_INSTITUTION")
AI_DESCRIPTION = os.getenv("AI_DESCRIPTION")
AI_LIMITATIONS = os.getenv("AI_LIMITATIONS")
AI_RESPONDER_STYLE = os.getenv("AI_RESPONDER_STYLE")

# ─── AUTENTICACIÓN ────────────────────────────────────────────────────────────

@routes.route('/')
def root():
    return redirect(url_for('routes.login'))

@routes.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email    = request.form.get('email')
        password = request.form.get('password')
        role     = request.form.get('role')

        user = User.query.filter_by(email=email).first()

        if not user:
            flash("Usuario no encontrado", "error")
            return render_template('login.html')

        # Validar que el rol enviado coincide con el rol del usuario
        if role == 'student' and user.role != 'alumno':
            flash("Este email no pertenece a un alumno", "error")
            return render_template('login.html')
        elif role == 'staff' and user.role not in ['profesor', 'admin']:
            flash("Este email no pertenece a un profesor o admin", "error")
            return render_template('login.html')

        # Validar contraseña
        if user.check_password(password):
            login_session['user_id']   = user.id
            login_session['user_name'] = user.first_name
            login_session['user_memory'] = user.customize_ai

            # Redirigir a panel según rol
            if user.role == 'admin':
                return redirect(url_for('routes.admin_panel'))
            elif user.role == 'profesor':
                return redirect(url_for('routes.subir_conocimiento'))
            elif user.role == 'alumno':
                return redirect(url_for('routes.chat_index'))
        else:
            flash("Contraseña incorrecta", "error")

    return render_template('login.html')

@routes.route("/logout", methods=["POST"])
def logout():
    login_session.clear()
    return jsonify({"success": True}), 200

# ─── ADMIN ────────────────────────────────────────────────────────────

@routes.route('/admin/panel')
def admin_panel():
    if 'user_id' not in login_session:
        return redirect(url_for('routes.login'))

    user = User.query.get(login_session['user_id'])
    if user.role != 'admin':
        flash("No autorizado", "error")
        return redirect(url_for('routes.chat_index'))

    return render_template('admin_panel.html')

@routes.route('/send_invitation', methods=['POST'])
def send_invitation():
    user_id = session.get('user_id')
    user = db.session.get(User, user_id)
    if not is_admin(user):
        return redirect(url_for('routes.login'))

    email = request.form['email']
    first = request.form['first_name']
    last = request.form['last_name']
    role = request.form['role']

    token = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + timedelta(days=2)

    invitation = InviteToken(email=email, token=token, role=role,
                             first_name=first, last_name=last,
                             expires_at=expires)
    db.session.add(invitation)
    db.session.commit()

    # Enlace de invitación
    link = url_for('routes.accept_invitation', token=token, _external=True)

    # Enviar correo con plantilla
    send_invitation_email(
        to_email=email,
        first_name=first,
        invite_url=link,
        expiration="48 horas"
    )

    flash("Invitación enviada con éxito", "success")
    return redirect(url_for('routes.admin_panel'))

# ─── REGISTRO ────────────────────────────────────────────────────────────

@routes.route('/registro/aceptar', methods=['GET', 'POST'])
def accept_invitation():
    token_str = request.args.get('token')
    token_obj = InviteToken.query.filter_by(token=token_str).first()

    if not token_obj or not token_obj.is_valid():
        return "Invitación no válida o expirada."

    if request.method == 'POST':
        password = request.form['password']
        new_user = User(
            email=token_obj.email,
            first_name=token_obj.first_name,
            last_name=token_obj.last_name,
            role=token_obj.role
        )
        new_user.password_hash = generate_password_hash(password)
        db.session.add(new_user)
        db.session.delete(token_obj)
        db.session.commit()
        flash("Cuenta creada exitosamente", "success")
        return redirect(url_for('routes.login'))

    return render_template("register_from_invite.html", email=token_obj.email)

# ─── MEMORIA ────────────────────────────────────────────────────────────

@routes.route('/memory', methods=['GET', 'POST'])
def edit_memory():
    if 'user_id' not in login_session:
        return redirect(url_for('routes.login'))

    user_id = login_session['user_id']
    user = User.query.get(user_id)

    # Si no hay memoria, inicializar con string vacío (por seguridad)
    if user.customize_ai is None:
        user.customize_ai = ""

    if request.method == 'POST':
        text = request.form.get('customize_ai', '').strip()
        user.customize_ai = text
        db.session.commit()

        # Opcional: actualizar la sesión si la usás en la IA
        login_session['user_memory'] = text

        flash("Memoria de usuario actualizada", "success")
        return redirect(url_for('routes.chat_index'))

    return render_template('memory.html', customize_ai=user.customize_ai)

# ─── Subir contenido ───────────────────────────────────────────────────────────
@routes.route('/conocimiento/subir', methods=['GET', 'POST'])
def subir_conocimiento():
    if 'user_id' not in login_session:
        return redirect(url_for('routes.login'))

    user_id = login_session['user_id']
    user = User.query.get(user_id)

    if user.role not in ['profesor', 'alumno']:
        flash("Acceso no autorizado", "error")
        return redirect(url_for('routes.chat_index'))

    if request.method == 'POST':
        file = request.files.get('file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            user_folder = os.path.join(current_app.config['UPLOAD_ROOT'], 'conocimiento', user.role, str(user_id))
            os.makedirs(user_folder, exist_ok=True)
            filepath = os.path.join(user_folder, filename)
            file.save(filepath)

            # Instanciamos la KB del usuario (esto crea la carpeta si no existía)
            kb = KnowledgeBase(f"{user.role}_{user_id}")

# Procesamos el archivo (extrae texto con los extractores disponibles)
            texto = procesar_archivo(filepath)

# Log para debugging (verifica en consola qué texto llegó)
            current_app.logger.info("Texto extraído (primeros 800 chars): %s", (texto or "")[:800])

            if not texto or not texto.strip():
    # Garantizamos que exista index.json (aunque vacío)
                try:
                    kb.save_documents()
                except Exception as e:
                    current_app.logger.exception("Error al crear index.json: %s", e)
                flash("⚠️ No se pudo extraer texto del archivo (ver logs).", "warning")
            else:
                doc_id = str(uuid.uuid4())
                meta = {
                    "filename": filename,
                    "uploaded_by": user_id,
                    "uploaded_at": datetime.utcnow().isoformat()
                }
                try:
                    kb.add_document(doc_id, texto, meta=meta)
                    flash("📚 Archivo cargado y procesado", "success")
                except Exception as e:
                    logger.exception("Error guardando documento en la KB: %s", e)
                    flash("⚠️ Error al indexar el documento en la base de conocimiento.", "error")
                    
    return render_template('subir_conocimiento.html')

@routes.route('/conocimiento/ver')
def ver_conocimiento():
    if 'user_id' not in login_session:
        return redirect(url_for('routes.login'))

    user_id = login_session['user_id']
    user = User.query.get(user_id)

    user_folder = os.path.join(current_app.config['UPLOAD_ROOT'], 'conocimiento', user.role, str(user_id))
    if not os.path.exists(user_folder):
        files = []
    else:
        files = os.listdir(user_folder)

    return render_template('ver_conocimiento.html', files=files, role=user.role)

# ─── CHAT PRINCIPAL ───────────────────────────────────────────────────────────

@routes.route('/chat', methods=['GET'])
def chat_index():
    if 'user_id' not in login_session:
        return redirect(url_for('routes.login'))
    user_id = login_session['user_id']
    sessions = ChatSession.query.filter_by(user_id=user_id).order_by(ChatSession.updated_at.desc()).all()
    user = User.query.get(user_id)
    full_name = f"{user.first_name} {user.last_name}"
    return render_template('chat_index.html', sessions=sessions, user_name=user.first_name, full_name=full_name, selected_session_id=None)

@routes.route("/chat/sessions", methods=["POST"])
def create_session():
    mode = request.form.get("mode", "text")
    user_id = login_session.get("user_id")
    if not user_id:
        return jsonify({"error": "no autorizado"}), 401

    if request.is_json:
        prompt = request.get_json().get("prompt", "").strip()
    else:
        prompt = request.form.get("prompt", "").strip()

    new_session = ChatSession(user_id=user_id, name=prompt[:30] + "..." if prompt else "Nuevo chat")
    db.session.add(new_session)
    db.session.commit()

    if prompt:
        new_message = ChatMessage(
            session_id=new_session.id,
            sender="user",
            text=prompt,
            timestamp=datetime.utcnow()
        )
        db.session.add(new_message)
        db.session.commit()

    return jsonify({
        "id": new_session.id,
        "session_url": url_for("routes.view_session", session_id=new_session.id)
    })

@routes.route('/chat/session/<int:session_id>', methods=['GET'])
def view_session(session_id):
    if 'user_id' not in login_session:
        return redirect(url_for('routes.login'))
    user_id = login_session['user_id']
    sess = ChatSession.query.get_or_404(session_id)
    user = User.query.get(user_id)
    full_name = f"{user.first_name} {user.last_name}"
    if sess.user_id != login_session['user_id']:
        flash("No autorizado", "error")
        return redirect(url_for('routes.chat_index'))
    messages = ChatMessage.query.filter_by(session_id=session_id)\
                               .order_by(ChatMessage.timestamp).all()
    files    = File.query.filter_by(session_id=session_id)\
                         .order_by(File.uploaded_at).all()
    return render_template(
        'chat_session.html',
        session=sess,
        messages=messages,
        files=files,
        selected_session_id=session_id,
        user_name=user.first_name,
        full_name=full_name
    )

@routes.route('/chat/session/<int:session_id>/rename', methods=['POST'])
def rename_session(session_id):
    if 'user_id' not in login_session:
        return jsonify({'error': 'no autorizado'}), 401
    new_name = request.form.get('name', '').strip()
    sess = ChatSession.query.get_or_404(session_id)
    if sess.user_id != login_session['user_id']:
        return jsonify({'error': 'no autorizado'}), 403
    if new_name:
        sess.name = new_name
        db.session.commit()
        return jsonify({'success': True, 'name': new_name})
    return jsonify({'error': 'nombre inválido'}), 400

@routes.route('/chat/session/<int:session_id>/delete', methods=['POST'])
def delete_session(session_id):
    if 'user_id' not in login_session:
        return jsonify({'error': 'no autorizado'}), 401
    sess = ChatSession.query.get_or_404(session_id)
    if sess.user_id != login_session['user_id']:
        return jsonify({'error': 'no autorizado'}), 403
    db.session.delete(sess)
    db.session.commit()
    return jsonify({'success': True})

@routes.route("/stream_chat/<int:session_id>", methods=["POST"])
def stream_chat(session_id: int) -> Response:
    # 1. Autenticación básica
    if 'user_id' not in login_session:
        return ("no autorizado", 401)

    sess = ChatSession.query.get_or_404(session_id)
    if sess.user_id != login_session['user_id']:
        return ("forbidden", 403)

    # 2. Obtener prompt del request
    prompt = (request.form.get("prompt") or "").strip()
    if not prompt:
        return ("Empty prompt", 400)

    # 3. Guardar mensaje del usuario en DB
    user_message = ChatMessage(
        session_id=session_id,
        sender="user",
        text=strip_think_all(prompt),
        timestamp=datetime.utcnow()
    )
    db.session.add(user_message)
    db.session.commit()

    # 4. Crear mensaje del asistente ANTES del streaming
    assistant_message = ChatMessage(
        session_id=session_id,
        sender="assistant",
        text="",  # Empezamos con texto vacío
        timestamp=datetime.utcnow()
    )
    db.session.add(assistant_message)
    db.session.commit()
    
    # Guardamos el ID del mensaje para actualizarlo
    assistant_msg_id = assistant_message.id

    kb = KnowledgeBase(namespace=str(session_id))
    upload_root = current_app.config.get("UPLOAD_ROOT", os.path.join(os.getcwd(), "uploads"))

    # 5. Recuperar historial antes del generator
    history = ChatMessage.query.filter_by(session_id=session_id).order_by(ChatMessage.timestamp).all()

    def event_stream() -> Generator[str, None, None]:
        accumulated_text = ""
        think_stripper = ThinkStripper()
        
        try:
            # Recuperar documentos relevantes
            try:
                retrieved = kb.retrieve_relevant_documents(prompt, top_k=3)
            except Exception:
                retrieved = []

            # Construir historial estilo ChatGPT
            model_prompt_parts = []
            for msg in history[:-1]:  # Excluimos el último mensaje (el del asistente vacío)
                if msg.sender == "user":
                    model_prompt_parts.append(f"Usuario: {msg.text}")
                else:
                    model_prompt_parts.append(f"Asistente: {msg.text}")

            for d in retrieved:
                t = d.get("text") or d.get("summary") or ""
                if t:
                    model_prompt_parts.append("KB: " + (t if len(t) < 1000 else t[:1000] + "..."))

            model_prompt = "\n\n".join(model_prompt_parts)

            # Llamar al modelo
            try:
                llm_result = ollama_run_for_kb(model_prompt, namespace=str(session_id), top_k=3)
            except Exception as e:
                logger.warning("LLM bridge failed: %s", e)
                error_msg = "Lo siento, el servicio de IA no está disponible en este momento."
                yield _sse_json_event({"chunk": error_msg})
                accumulated_text = error_msg
                return

            # Stream de chunks y acumulación
            if isinstance(llm_result, list):
                for item in llm_result:
                    chunk = item.get("text") or str(item)
                    cleaned = think_stripper.feed(chunk)
                    if cleaned:
                        accumulated_text += cleaned
                        
                        # Actualizar en BD cada chunk (opcional, para más robustez)
                        try:
                            with current_app.app_context():
                                msg_to_update = ChatMessage.query.get(assistant_msg_id)
                                if msg_to_update:
                                    msg_to_update.text = _sanitize_persist(accumulated_text)
                                    db.session.commit()
                        except Exception as e:
                            logger.warning(f"Error updating message in DB: {e}")
                        
                        yield _sse_json_event({"chunk": cleaned})
            else:
                chunk = str(llm_result)
                cleaned = think_stripper.feed(chunk)
                if cleaned:
                    accumulated_text += cleaned
                    yield _sse_json_event({"chunk": cleaned})

        except GeneratorExit:
            logger.info("SSE client disconnected for session %s", session_id)
        except Exception as e:
            logger.exception("Unexpected error in stream_chat: %s", e)
            try:
                yield _sse_json_event({"error": "Internal server error"})
            except Exception:
                pass
        finally:
            # GUARDAR FINAL: Esto se ejecuta SIEMPRE, incluso si el cliente desconecta
            if accumulated_text:
                try:
                    # finalize stripper (discard any open <think>...)
                    try:
                        think_stripper.finalize()
                    except Exception:
                        pass
                    with current_app.app_context():
                        msg_to_update = ChatMessage.query.get(assistant_msg_id)
                        if msg_to_update:
                            final_text = _sanitize_persist(accumulated_text)
                            msg_to_update.text = final_text
                            msg_to_update.timestamp = datetime.utcnow()  # Actualizar timestamp
                            db.session.commit()
                            logger.info(f"Final message saved to DB: {len(final_text)} chars")
                except Exception as e:
                    logger.error(f"Error saving final message to DB: {e}")

    # 6. Devolver streaming response
    response = Response(
        stream_with_context(event_stream()), 
        content_type="text/event-stream; charset=utf-8"
    )
    
    # Headers importantes para SSE
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['Connection'] = 'keep-alive'
    response.headers['X-Accel-Buffering'] = 'no'  # Para nginx

    return response




@routes.route('/tts/<filename>')
def get_tts(filename):
    tts_path = os.path.join(current_app.config['UPLOAD_ROOT'], 'tts')
    return send_from_directory(tts_path, filename)

@routes.route('/chat/download/<int:file_id>', methods=['GET'])
def download_file(file_id):
    if 'user_id' not in login_session:
        return redirect(url_for('routes.login'))

    f = File.query.get_or_404(file_id)
    if f.user_id != login_session['user_id']:
        flash("No autorizado", "error")
        return redirect(url_for('routes.chat_index'))

    directory = os.path.dirname(f.filepath)
    return send_from_directory(directory, f.filename, as_attachment=True)
