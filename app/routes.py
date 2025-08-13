import os
import re
import json
from flask import Blueprint, request, session as login_session, redirect, url_for, render_template, flash, jsonify, current_app, send_from_directory, session, Response, stream_with_context, request, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from app.knowledge_base import KnowledgeBase
from .models import db, User, ChatSession, ChatMessage, File
from werkzeug.security import generate_password_hash
from app.file_reader import procesar_archivo
import uuid
import edge_tts, asyncio
from dotenv import load_dotenv
import threading
import signal
from datetime import datetime
import secrets
from datetime import timedelta
from .models import InviteToken
from .utils import send_invitation_email
from app.ollama_stream import stream_chat_for_user, chat_once, limpiar_output
from flask import Response, stream_with_context
from datetime import datetime
import json
import threading
from datetime import datetime
import time
load_dotenv()

routes = Blueprint('routes', __name__)

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

            texto = procesar_archivo(filepath)
            if not texto.strip():
                flash("⚠️ No se pudo extraer texto del archivo", "warning")
            else:
                kb = KnowledgeBase(f"{user.role}_{user_id}")
                kb.add_document(texto)
                flash("📚 Archivo cargado y procesado", "success")

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

# ═══ NUEVA RUTA DE CHAT LIMPIA (usando solo ollama_stream) - SIN LIMPIEZA DE RESPUESTAS ═══
@routes.route('/stream_chat/<int:session_id>', methods=['POST'])
def stream_chat_route(session_id):
    """Ruta principal para chat streaming usando ollama_stream.py mejorado - VERSION SIN LIMPIEZA"""
    # --- Autenticación ---
    if 'user_id' not in login_session:
        return jsonify({'error': 'no autorizado'}), 401

    user_id = login_session['user_id']
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'no autorizado'}), 401

    # --- Validar sesión ---
    chat_sess = ChatSession.query.get_or_404(session_id)
    if chat_sess.user_id != user_id:
        return jsonify({'error': 'no autorizado'}), 403

    # --- Obtener prompt y archivo ---
    prompt = ""
    final_text = ""
    file = None

    content_type = request.content_type or ""
    if content_type.startswith('multipart/form-data'):
        prompt = (request.form.get('prompt') or "").strip()
        file = request.files.get('file')
    else:
        data = request.get_json(silent=True) or {}
        prompt = (data.get('prompt') or "").strip()

    # --- Manejar archivo (si existe) ---
    if file and allowed_file(file.filename):
        base = os.path.join(current_app.config['UPLOAD_ROOT'], str(user_id), str(session_id))
        os.makedirs(base, exist_ok=True)
        filename = secure_filename(file.filename)
        filepath = os.path.join(base, filename)
        file.save(filepath)

        nuevo = File(session_id=session_id, user_id=user_id, filename=filename, filepath=filepath)
        db.session.add(nuevo)
        db.session.commit()

        texto_archivo = procesar_archivo(filepath)
        if not texto_archivo.strip():
            texto_archivo = "⚠️ No se pudo extraer texto del archivo."

        final_text += f"[Archivo: {filename}] {texto_archivo[:1500]} "

    if prompt:
        final_text += f"\n{prompt}"

    if not final_text.strip():
        return jsonify({'error': 'mensaje vacío'}), 400

    # --- Guardar mensaje de usuario ---
    user_msg = ChatMessage(
        session_id=session_id,
        sender='user',
        text=final_text.strip(),
        timestamp=datetime.utcnow()
    )
    db.session.add(user_msg)
    db.session.commit()

    # --- Preparar contexto ---
    profile = User.query.get(user_id)
    full_memory = profile.customize_ai or ""
    memory_to_use = full_memory

    # Resumir memoria si es muy larga (usando chat_once mejorado)
    if len(full_memory) > 5000:
        try:
            summary_messages = [
                {"role": "system", "content": "Resume brevemente el siguiente texto en máximo 200 palabras."},
                {"role": "user", "content": full_memory}
            ]
            summary = chat_once(
                summary_messages, 
                model=current_app.config.get('OLLAMA_MODEL', 'deepseek-r1:14b'), 
                timeout=20
            )
            memory_to_use = summary.strip() or full_memory[:4000]
        except Exception as e:
            current_app.logger.exception("Error al resumir memory: %s", e)
            memory_to_use = full_memory[:4000]

    # --- Obtener KB relevante ---
    kb = KnowledgeBase(f"{profile.role}_{user_id}")
    kb_context = kb.retrieve_relevant_documents(final_text) or ""

    # --- Modelo y configuración ---
    model_name = current_app.config.get('OLLAMA_MODEL', 'deepseek-r1:14b')
    timeout = current_app.config.get('OLLAMA_CALL_TIMEOUT', 60)
    
    # Configurar debug si es necesario (opcional)
    if current_app.debug or current_app.config.get('DEBUG_OLLAMA_PROCESSING'):
        from app.ollama_stream import set_debug_mode
        set_debug_mode(True)

    # --- Generador SSE Mejorado - SIN LIMPIEZA ---
    def generate():
        accumulated = ""
        chunk_count = 0
        last_chunk_time = time.time()
        
        try:
            current_app.logger.info(f"🚀 Iniciando stream SIN LIMPIEZA para sesión {session_id}")
            
            # Usar stream_chat_for_user del módulo ollama_stream mejorado
            stream = stream_chat_for_user(
                user_customize_ai=memory_to_use,
                kb_context=kb_context,
                prompt=final_text,
                model=model_name,
                timeout=timeout
            )

            for chunk in stream:
                if not chunk:
                    continue
                
                chunk_count += 1
                current_time = time.time()
                
                # Log para debugging (solo en desarrollo)
                if current_app.debug:
                    current_app.logger.debug(
                        f"Chunk #{chunk_count}: {len(chunk)} chars, "
                        f"gap: {current_time - last_chunk_time:.2f}s, "
                        f"raw_chunk: {repr(chunk[:50])}"  # Mostrar chunk crudo para debug
                    )
                
                last_chunk_time = current_time
                
                # ✅ CAMBIO CRÍTICO: NO procesar el chunk, usarlo tal como viene
                # chunk_text = str(chunk).strip()  # <-- REMOVIDO
                chunk_text = str(chunk)  # Mantener chunk exactamente como viene
                
                # ✅ CAMBIO: Permitir chunks vacíos si vienen de la IA
                # if not chunk_text:  # <-- REMOVIDO
                #     continue         # <-- REMOVIDO
                
                # ✅ CAMBIO: NO modificar el texto del chunk
                # Acumular EXACTAMENTE como viene
                accumulated += chunk_text
                
                # ✅ CAMBIO: Escapar mínimamente para SSE sin alterar el contenido
                # Solo escapar lo esencial para que SSE funcione
                sse_chunk = chunk_text.replace('\n', '\\n').replace('\r', '\\r')
                
                # Emitir evento SSE
                yield f"data: {sse_chunk}\n\n"
                
                # Flush periódico para streaming suave
                if chunk_count % 10 == 0:
                    yield ""  # Keep-alive

            current_app.logger.info(f"✅ Stream SIN LIMPIEZA completado: {chunk_count} chunks, {len(accumulated)} chars totales")

        except GeneratorExit:
            current_app.logger.info("Cliente desconectado durante streaming")
            return
            
        except Exception as e:
            current_app.logger.exception("Error durante streaming desde Ollama: %s", e)
            error_msg = f"[ERROR] Error en el stream: {str(e)}"
            yield f"data: {error_msg}\n\n"
            accumulated += error_msg

        # --- Persistir respuesta completa - SIN MODIFICAR ---
        try:
            # ✅ CAMBIO CRÍTICO: NO limpiar el texto acumulado
            if accumulated:  # Cambiar de accumulated.strip() a solo accumulated
                # NO limpiar acumulado final - guardarlo exactamente como vino
                # final_accumulated = accumulated.strip()  # <-- REMOVIDO
                final_accumulated = accumulated  # ✅ Mantener texto original completo
                
                # Crear mensaje de respuesta
                ai_msg = ChatMessage(
                    session_id=session_id,
                    sender='assistant',
                    text=final_accumulated,  # Guardar exactamente como vino de la IA
                    timestamp=datetime.utcnow()
                )
                db.session.add(ai_msg)
                
                # Actualizar timestamp de sesión
                chat_sess.updated_at = datetime.utcnow()
                db.session.commit()

                current_app.logger.info(f"✅ Mensaje AI guardado SIN MODIFICAR: ID {ai_msg.id}, {len(final_accumulated)} chars")

                # Enviar evento final con información
                try:
                    done_payload = json.dumps({
                        'message_id': ai_msg.id,
                        'char_count': len(final_accumulated),
                        'chunk_count': chunk_count,
                        'raw_response': True  # ✅ Indicador de que es respuesta sin procesar
                    })
                except Exception:
                    done_payload = '{"status": "completed", "raw_response": true}'
                
                yield f"data: [DONE] {done_payload}\n\n"

                # TTS en background (mejorado con manejo de errores)
                def generate_tts_background(message_id, text_to_speak):
                    """Genera TTS en background thread con manejo robusto de errores."""
                    try:
                        import edge_tts
                        import asyncio
                        
                        # Preparar directorio TTS
                        tts_dir = os.path.join(current_app.config['UPLOAD_ROOT'], 'tts')
                        os.makedirs(tts_dir, exist_ok=True)
                        
                        # Generar nombre único
                        tts_filename = f"{uuid.uuid4().hex}_edge.mp3"
                        tts_path = os.path.join(tts_dir, tts_filename)
                        
                        # ✅ CAMBIO: Para TTS SÍ limpiar (pero solo para audio, no para guardar)
                        clean_text = clean_text_for_tts(text_to_speak)
                        
                        # Crear y configurar event loop
                        try:
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)
                            
                            # Generar TTS
                            communicate = edge_tts.Communicate(
                                text=clean_text, 
                                voice="es-ES-AlvaroNeural"
                            )
                            
                            loop.run_until_complete(communicate.save(tts_path))
                            
                        finally:
                            loop.close()
                        
                        # Actualizar mensaje con ruta de audio
                        with current_app.app_context():
                            msg = ChatMessage.query.get(message_id)
                            if msg and os.path.exists(tts_path):
                                msg.audio_path = tts_filename
                                db.session.commit()
                                current_app.logger.info(f"TTS generado: {tts_filename}")
                            else:
                                current_app.logger.warning(f"No se pudo actualizar mensaje {message_id} con TTS")
                                
                    except Exception as e:
                        current_app.logger.error(f"Error en TTS background para mensaje {message_id}: {e}")

                # ✅ CAMBIO: Lanzar TTS solo si hay contenido (sin strip)
                if len(final_accumulated) > 10:
                    threading.Thread(
                        target=generate_tts_background, 
                        args=(ai_msg.id, final_accumulated),
                        daemon=True,
                        name=f"TTS-{ai_msg.id}"
                    ).start()
                
            else:
                current_app.logger.warning("Stream completado pero sin contenido acumulado")
                yield f"data: [WARNING] Stream completado sin contenido\n\n"

        except Exception as e:
            current_app.logger.exception("Error crítico guardando ChatMessage final: %s", e)
            try:
                db.session.rollback()
            except Exception as rollback_error:
                current_app.logger.error(f"Error en rollback: {rollback_error}")
            
            # Informar error al cliente
            yield f"data: [ERROR] Error guardando respuesta: {str(e)}\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')


def clean_text_for_tts(text: str) -> str:
    """
    Limpia texto para TTS removiendo markdown y elementos problemáticos.
    ✅ NOTA: Esta función SÍ limpia, pero SOLO para generar audio TTS,
    NO afecta el texto que se guarda en la base de datos.
    """
    if not text:
        return ""
    
    # Remover bloques de código
    text = re.sub(r'```[\s\S]*?```', ' [código] ', text)
    text = re.sub(r'`[^`]+`', ' [código] ', text)
    
    # Remover enlaces markdown
    text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
    
    # Remover formatting markdown
    text = re.sub(r'\*\*([^*]+)\*\*', r'\1', text)  # Bold
    text = re.sub(r'\*([^*]+)\*', r'\1', text)      # Italic
    text = re.sub(r'__([^_]+)__', r'\1', text)      # Bold alt
    text = re.sub(r'_([^_]+)_', r'\1', text)        # Italic alt
    
    # Remover headers
    text = re.sub(r'^#+\s+', '', text, flags=re.MULTILINE)
    
    # Remover listas
    text = re.sub(r'^\s*[-*+]\s+', '', text, flags=re.MULTILINE)
    text = re.sub(r'^\s*\d+\.\s+', '', text, flags=re.MULTILINE)
    
    # Limpiar espacios múltiples
    text = re.sub(r'\s+', ' ', text)
    
    # Limitar longitud para TTS
    if len(text) > 500:
        text = text[:500] + "..."
    
    return text.strip()


# Función auxiliar para debugging de streams - MEJORADA
def debug_stream_info(session_id: int, user_id: int, final_text: str):
    """Log información útil para debugging de streams."""
    if not current_app.debug:
        return
        
    current_app.logger.debug(f"""
    === STREAM DEBUG INFO (SIN LIMPIEZA) ===
    Session ID: {session_id}
    User ID: {user_id}
    Text length: {len(final_text)}
    Text preview: {repr(final_text[:100])}...
    Model: {current_app.config.get('OLLAMA_MODEL', 'default')}
    Timeout: {current_app.config.get('OLLAMA_CALL_TIMEOUT', 60)}
    Raw responses: ENABLED ✅
    Text cleaning: DISABLED ✅
    ========================================
    """)

# ✅ NUEVA FUNCIÓN DE UTILIDAD
def get_stream_processing_status():
    """
    Función para verificar el estado de procesamiento de streams.
    Útil para debugging y monitoring.
    """
    return {
        "text_cleaning": False,
        "chunk_processing": False,
        "preserve_formatting": True,
        "preserve_whitespace": True,
        "preserve_special_chars": True,
        "raw_ai_responses": True,
        "version": "no-clean-v1.0"
    }

# ✅ NUEVA FUNCIÓN PARA TESTING
def test_raw_streaming():
    """
    Función de prueba para verificar que el streaming mantiene
    el texto exactamente como lo genera la IA.
    """
    status = get_stream_processing_status()
    current_app.logger.info(f"🧪 Estado de procesamiento: {status}")
    
    # Simular chunks con diferentes tipos de contenido
    test_chunks = [
        "Hola\n",           # Con salto de línea
        "  mundo  ",        # Con espacios
        "\t\tcon tabs\t",   # Con tabs
        "**bold**",         # Con markdown
        "",                 # Chunk vacío
        "final."            # Chunk final
    ]
    
    accumulated = ""
    for i, chunk in enumerate(test_chunks):
        current_app.logger.debug(f"Test chunk #{i+1}: {repr(chunk)}")
        accumulated += chunk  # Acumular sin modificar
    
    current_app.logger.info(f"✅ Resultado acumulado: {repr(accumulated)}")
    return accumulated

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
