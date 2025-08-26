
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
from typing import Generator, List, Dict

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

def analizar_nivel_comprension(historial_mensajes: list) -> str:
    """
    Analiza el historial de mensajes para determinar el nivel de comprensión
    del estudiante y sugerir estrategias pedagógicas específicas.
    """
    if not historial_mensajes:
        return "primer_contacto"
    
    # Obtener los últimos mensajes del estudiante
    mensajes_estudiante = [msg for msg in historial_mensajes if msg.sender == "user"]
    
    # Indicadores de confusión
    indicadores_confusion = [
        "no entiendo", "no comprendo", "confuso", "difícil", "complicado",
        "puedes explicar", "no me queda claro", "otra vez", "repetir",
        "más fácil", "más simple", "ayuda", "no sé"
    ]
    
    # Indicadores de comprensión
    indicadores_comprension = [
        "entendí", "claro", "perfecto", "correcto", "gracias",
        "ahora sí", "ya veo", "tiene sentido", "comprendo"
    ]
    
    if not mensajes_estudiante:
        return "primer_contacto"
    
    ultimos_3_mensajes = mensajes_estudiante[-3:]
    texto_reciente = " ".join([msg.text.lower() for msg in ultimos_3_mensajes])
    
    # Contar indicadores
    confusion_count = sum(1 for indicador in indicadores_confusion if indicador in texto_reciente)
    comprension_count = sum(1 for indicador in indicadores_comprension if indicador in texto_reciente)
    
    # Análisis de patrones
    if confusion_count > comprension_count and confusion_count >= 2:
        return "necesita_refuerzo_mayor"
    elif confusion_count > 0:
        return "necesita_refuerzo_menor" 
    elif comprension_count > 0:
        return "comprendiendo_bien"
    else:
        return "nivel_normal"
    
def construir_system_prompt_con_conocimiento(user_id: int, historial_mensajes: list = None) -> str:
    """
    Construye un system prompt que incluye TODO el conocimiento institucional
    disponible para garantizar que la IA siempre tenga acceso completo.
    """
    # Analizar nivel de comprensión del estudiante
    nivel_comprension = analizar_nivel_comprension(historial_mensajes or [])
    
    # Variables de entorno base
    ai_name = os.getenv("AI_NAME", "Asistente IA")
    ai_institution = os.getenv("AI_INSTITUTION", "")
    ai_description = os.getenv("AI_DESCRIPTION", "Soy un asistente útil")
    ai_style = os.getenv("AI_RESPONDER_STYLE", "claro y conciso")
    ai_limitations = os.getenv("AI_LIMITATIONS", "")
    
    # Construir prompt base
    system_parts = [f"Eres {ai_name}"]
    if ai_institution:
        system_parts.append(f"de {ai_institution}")
    
    system_parts.append(f". {ai_description}")
    system_parts.append(f"Respondes de manera {ai_style} y siempre en español.")
    
    if ai_limitations:
        system_parts.append(f"Limitaciones: {ai_limitations}")
    
    # Adaptación según nivel de comprensión detectado
    adaptaciones_pedagogicas = {
        "primer_contacto": "\n🎯 MODO: Establecimiento de rapport - Se amigable y evalúa el nivel inicial.",
        "necesita_refuerzo_mayor": "\n🚨 MODO: Refuerzo intensivo - El estudiante tiene dificultades importantes. Usa explicaciones MUY básicas, muchas analogías y verificación constante.",
        "necesita_refuerzo_menor": "\n⚠️ MODO: Refuerzo ligero - El estudiante tiene algunas dudas. Explica con más detalle y verifica comprensión frecuentemente.",
        "comprendiendo_bien": "\n✅ MODO: Avance normal - El estudiante comprende bien. Puedes mantener el ritmo pero sigue verificando.",
        "nivel_normal": "\n📚 MODO: Enseñanza estándar - Aplica la metodología pedagógica estándar."
    }
    
    system_parts.append(adaptaciones_pedagogicas.get(nivel_comprension, adaptaciones_pedagogicas["nivel_normal"]))
    
    # 🔥 NUEVA FUNCIONALIDAD: Cargar TODO el conocimiento institucional
    try:
        kb_institucional = KnowledgeBase("institucional")
        documentos_institucionales = kb_institucional.documents
        
        if documentos_institucionales:
            system_parts.append("\n=== CONOCIMIENTO INSTITUCIONAL COMPLETO ===")
            system_parts.append("Tienes acceso a todo este material educativo institucional:")
            
            for i, doc in enumerate(documentos_institucionales, 1):
                texto = doc.get("text", "")
                meta = doc.get("meta", {})
                
                if texto:
                    # Información sobre el documento
                    doc_info = f"\n--- DOCUMENTO {i} ---"
                    if meta.get("filename"):
                        doc_info += f"\nArchivo: {meta['filename']}"
                    if meta.get("uploaded_by_name"):
                        doc_info += f"\nSubido por: {meta['uploaded_by_name']} ({meta.get('uploaded_by_role', 'N/A')})"
                    if meta.get("uploaded_at"):
                        doc_info += f"\nFecha: {meta['uploaded_at'][:10]}"
                    
                    system_parts.append(doc_info)
                    
                    # Contenido completo del documento
                    # Limitar a 3000 chars por documento para evitar prompts muy largos
                    if len(texto) > 3000:
                        texto_resumido = texto[:3000] + "\n[...contenido truncado...]"
                        system_parts.append(f"\nContenido:\n{texto_resumido}")
                    else:
                        system_parts.append(f"\nContenido:\n{texto}")
            
            system_parts.append("\n=== FIN DEL CONOCIMIENTO INSTITUCIONAL ===")
            system_parts.append("\nUSA ESTE CONOCIMIENTO para responder preguntas relacionadas con el material educativo.")
            system_parts.append("Siempre cita la fuente cuando uses información específica de estos documentos.")
        
    except Exception as e:
        logger.warning(f"Error cargando conocimiento institucional: {e}")
        system_parts.append("\n[Nota: Conocimiento institucional no disponible en este momento]")
    
    # 🔥 OPCIONAL: Cargar también el conocimiento personal del alumno
    try:
        kb_personal = KnowledgeBase(f"alumno_{user_id}")
        documentos_personales = kb_personal.documents
        
        if documentos_personales:
            system_parts.append("\n=== MATERIAL PERSONAL DEL ESTUDIANTE ===")
            system_parts.append("También tienes acceso al material personal que ha subido este estudiante:")
            
            for i, doc in enumerate(documentos_personales, 1):
                texto = doc.get("text", "")
                meta = doc.get("meta", {})
                
                if texto:
                    doc_info = f"\n--- DOCUMENTO PERSONAL {i} ---"
                    if meta.get("filename"):
                        doc_info += f"\nArchivo: {meta['filename']}"
                    
                    system_parts.append(doc_info)
                    
                    # Contenido limitado para documentos personales
                    if len(texto) > 1500:
                        texto_resumido = texto[:1500] + "\n[...contenido truncado...]"
                        system_parts.append(f"\nContenido:\n{texto_resumido}")
                    else:
                        system_parts.append(f"\nContenido:\n{texto}")
            
            system_parts.append("\n=== FIN DEL MATERIAL PERSONAL ===")
    
    except Exception as e:
        logger.debug(f"Sin material personal para usuario {user_id}: {e}")
    
    # 🎯 INSTRUCCIONES PEDAGÓGICAS AVANZADAS
    system_parts.append("\n=== ESTILO DE ENSEÑANZA REQUERIDO ===")
    
    # Uso de emojis educativos
    system_parts.append("\n📚 USO DE EMOJIS:")
    system_parts.append("- Usa emojis relevantes para hacer el aprendizaje más visual y amigable")
    system_parts.append("- Ejemplos: 📝 para tareas, ✅ para conceptos correctos, ❓ para dudas, 💡 para ideas clave")
    system_parts.append("- 🔍 para análisis, 📊 para datos, 🎯 para objetivos, ⚠️ para advertencias")
    
    # Metodología de enseñanza pausada
    system_parts.append("\n🐌 ENSEÑANZA PAUSADA Y ESTRUCTURADA:")
    system_parts.append("- Explica conceptos de forma gradual, paso a paso")
    system_parts.append("- Divide temas complejos en subtemas pequeños y manejables")
    system_parts.append("- Después de cada explicación importante, pregunta: '¿Vas entendiendo hasta aquí?' o '¿Necesitas que profundice en algún punto?'")
    system_parts.append("- Usa analogías y ejemplos simples para conceptos difíciles")
    system_parts.append("- No avances al siguiente punto hasta confirmar comprensión")
    
    # Sistema de detección de incomprensión
    system_parts.append("\n🚨 DETECCIÓN DE DIFICULTADES:")
    system_parts.append("- Si detectas confusión (preguntas repetitivas, respuestas vagas, frustración), CAMBIA tu método")
    system_parts.append("- Opciones de re-explicación:")
    system_parts.append("  • Usar analogías más simples")
    system_parts.append("  • Dividir en pasos aún más pequeños")
    system_parts.append("  • Usar ejemplos visuales o cotidianos")
    system_parts.append("  • Preguntar específicamente qué parte no quedó clara")
    system_parts.append("- Nunca asumas comprensión, siempre verifica")
    
    # Sistema de ejercicios automáticos
    system_parts.append("\n📝 EJERCICIOS DESPUÉS DE CADA TEMA:")
    system_parts.append("- Después de explicar un concepto completo, SIEMPRE propón un ejercicio práctico")
    system_parts.append("- Tipos de ejercicios:")
    system_parts.append("  • Preguntas de comprensión")
    system_parts.append("  • Problemas prácticos relacionados")
    system_parts.append("  • Casos de estudio")
    system_parts.append("  • Aplicaciones del mundo real")
    system_parts.append("- Adapta la dificultad según el nivel mostrado por el estudiante")
    
    # Verificación constante de comprensión
    system_parts.append("\n✅ VERIFICACIÓN CONTINUA:")
    system_parts.append("- Usa frases como:")
    system_parts.append("  • '¿Te queda claro este punto antes de continuar?'")
    system_parts.append("  • '¿Puedes explicarme con tus propias palabras lo que acabamos de ver?'")
    system_parts.append("  • '¿Hay algo de esto que te genere dudas?'")
    system_parts.append("  • '¿Vamos bien o necesitas que repase algún concepto?'")
    
    # Adaptación pedagógica
    system_parts.append("\n🔄 ADAPTACIÓN INTELIGENTE:")
    system_parts.append("- Si un estudiante responde correctamente: avanza gradualmente")
    system_parts.append("- Si muestra dificultades: retrocede y explica de manera más básica")
    system_parts.append("- Si hace preguntas avanzadas: puedes profundizar más")
    system_parts.append("- Mantén siempre un tono alentador y paciente")
    
    # Estructura de respuesta recomendada
    system_parts.append("\n📋 ESTRUCTURA DE RESPUESTA TÍPICA:")
    system_parts.append("1. 👋 Saludo amigable (si es pertinente)")
    system_parts.append("2. 📚 Contexto del tema")
    system_parts.append("3. 💡 Explicación paso a paso")
    system_parts.append("4. ❓ Verificación de comprensión")
    system_parts.append("5. 📝 Ejercicio práctico (después de completar un tema)")
    system_parts.append("6. 🎯 Siguiente paso o resumen")
    
    # Prioridades finales
    system_parts.append("\n🔴 PRIORIDADES:")
    system_parts.append("- NUNCA asumas que el estudiante entendió")
    system_parts.append("- SIEMPRE verifica comprensión antes de avanzar")
    system_parts.append("- El conocimiento institucional tiene prioridad sobre otras fuentes")
    system_parts.append("- La comprensión del estudiante es más importante que cubrir todo el contenido rápidamente")
    system_parts.append("- Sé paciente, empático y adaptable en tu enseñanza")
    
    return "\n".join(system_parts)

def _sanitize_persist(text: str) -> str:
    """
    Sanitiza el texto antes de persistirlo.
    Limpia caracteres problemÃƒÂ¡ticos y limita longitud.
    """
    if not text:
        return ""
    
    # Limitar longitud mÃƒÂ¡xima
    if len(text) > 10000:
        text = text[:10000] + "..."
    
    # Limpiar caracteres problemÃƒÂ¡ticos
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
    
    # ImÃƒÂ¡genes
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
        print("ADMIN_EMAIL o ADMIN_PASSWORD no estÃƒÂ¡n definidos en .env")
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
        print("Ã¢Å“â€¦ Usuario administrador creado")
    else:
        print("Ã¢â€žÂ¹Ã¯Â¸Â Usuario administrador ya existe")

def is_admin(user):
    return user.role == 'admin'

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def limpiar_output(texto):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    limpio = ansi_escape.sub('', texto)
    spinner_chars = "Ã¢ â€¹Ã¢ â„¢Ã¢ Â¹Ã¢ Â¸Ã¢ Â¼Ã¢ Â´Ã¢ Â¦Ã¢ Â§Ã¢ â€¡Ã¢ Â"
    limpio = ''.join(c for c in limpio if c not in spinner_chars)
    limpio = re.sub(r'\n{3,}', '\n\n', limpio)
    return limpio.strip()

# 2. FunciÃƒÂ³n auxiliar para recuperar documentos de mÃƒÂºltiples fuentes
def recuperar_documentos_multiples(prompt: str, user_id: int, session_id: int, top_k: int = 5) -> List[Dict]:
    """
    Recupera documentos relevantes de mÃƒÂºltiples fuentes de conocimiento.
    Prioriza contenido institucional (profesores) sobre contenido personal.
    """
    documentos = []
    
    # 1. PRIORIDAD ALTA: Contenido institucional (profesores y admins)
    try:
        kb_institucional = KnowledgeBase("institucional")
        docs_institucional = kb_institucional.retrieve_relevant_documents(prompt, top_k=3)
        for doc in docs_institucional:
            doc['source_priority'] = 1  # Mayor prioridad
            doc['source_type'] = 'institucional'
        documentos.extend(docs_institucional)
        logger.info(f"Encontrados {len(docs_institucional)} documentos institucionales")
    except Exception as e:
        logger.warning(f"Error accediendo a KB institucional: {e}")
    
    # 2. PRIORIDAD MEDIA: Archivos personales del alumno
    try:
        kb_personal = KnowledgeBase(f"alumno_{user_id}")
        docs_personales = kb_personal.retrieve_relevant_documents(prompt, top_k=2)
        for doc in docs_personales:
            doc['source_priority'] = 2
            doc['source_type'] = 'personal'
        documentos.extend(docs_personales)
        logger.info(f"Encontrados {len(docs_personales)} documentos personales")
    except Exception as e:
        logger.debug(f"Sin documentos personales para usuario {user_id}: {e}")
    
    # 3. PRIORIDAD BAJA: Contexto especÃƒÂ­fico de la sesiÃƒÂ³n
    try:
        kb_session = KnowledgeBase(str(session_id))
        docs_session = kb_session.retrieve_relevant_documents(prompt, top_k=1)
        for doc in docs_session:
            doc['source_priority'] = 3
            doc['source_type'] = 'session'
        documentos.extend(docs_session)
        logger.info(f"Encontrados {len(docs_session)} documentos de sesiÃƒÂ³n")
    except Exception as e:
        logger.debug(f"Sin documentos especÃƒÂ­ficos de sesiÃƒÂ³n {session_id}: {e}")
    
    # Ordenar por prioridad y limitar resultados
    documentos.sort(key=lambda x: x.get('source_priority', 999))
    return documentos[:top_k]

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

# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ AUTENTICACIÃƒâ€œN Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

        # Validar contraseÃƒÂ±a
        if user.check_password(password):
            login_session['user_id']   = user.id
            login_session['user_name'] = user.first_name
            login_session['user_memory'] = user.customize_ai

            # Redirigir a panel segÃƒÂºn rol
            if user.role == 'admin':
                return redirect(url_for('routes.admin_panel'))
            elif user.role == 'profesor':
                return redirect(url_for('routes.subir_conocimiento'))
            elif user.role == 'alumno':
                return redirect(url_for('routes.chat_index'))
        else:
            flash("ContraseÃƒÂ±a incorrecta", "error")

    return render_template('login.html')

@routes.route("/logout", methods=["POST"])
def logout():
    login_session.clear()
    return jsonify({"success": True}), 200

# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ ADMIN Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

    # Enlace de invitaciÃƒÂ³n
    link = url_for('routes.accept_invitation', token=token, _external=True)

    # Enviar correo con plantilla
    send_invitation_email(
        to_email=email,
        first_name=first,
        invite_url=link,
        expiration="48 horas"
    )

    flash("InvitaciÃƒÂ³n enviada con ÃƒÂ©xito", "success")
    return redirect(url_for('routes.admin_panel'))

# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ REGISTRO Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

@routes.route('/registro/aceptar', methods=['GET', 'POST'])
def accept_invitation():
    token_str = request.args.get('token')
    token_obj = InviteToken.query.filter_by(token=token_str).first()

    if not token_obj or not token_obj.is_valid():
        return "InvitaciÃƒÂ³n no vÃƒÂ¡lida o expirada."

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

# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ MEMORIA Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

@routes.route('/memory', methods=['GET', 'POST'])
def edit_memory():
    if 'user_id' not in login_session:
        return redirect(url_for('routes.login'))

    user_id = login_session['user_id']
    user = User.query.get(user_id)

    # Si no hay memoria, inicializar con string vacÃƒÂ­o (por seguridad)
    if user.customize_ai is None:
        user.customize_ai = ""

    if request.method == 'POST':
        text = request.form.get('customize_ai', '').strip()
        user.customize_ai = text
        db.session.commit()

        # Opcional: actualizar la sesiÃƒÂ³n si la usÃƒÂ¡s en la IA
        login_session['user_memory'] = text

        flash("Memoria de usuario actualizada", "success")
        return redirect(url_for('routes.chat_index'))

    return render_template('memory.html', customize_ai=user.customize_ai)

# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Subir contenido Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
@routes.route('/conocimiento/subir', methods=['GET', 'POST'])
def subir_conocimiento():
    if 'user_id' not in login_session:
        return redirect(url_for('routes.login'))

    user_id = login_session['user_id']
    user = User.query.get(user_id)

    if user.role not in ['profesor', 'alumno', 'admin']:
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

            # Ã°Å¸â€Â¥ CAMBIO PRINCIPAL: Namespace segÃƒÂºn el rol
            if user.role in ['profesor', 'admin']:
                # Profesores y admins suben al namespace institucional compartido
                namespace = "institucional"
                flash_msg = "Ã°Å¸â€œÅ¡ Archivo cargado al repositorio institucional"
            else:
                # Alumnos mantienen su namespace personal
                namespace = f"alumno_{user_id}"
                flash_msg = "Ã°Å¸â€œÅ¡ Archivo cargado a tu biblioteca personal"
            
            kb = KnowledgeBase(namespace)

            # Procesamos el archivo
            texto = procesar_archivo(filepath)
            current_app.logger.info("Texto extraÃƒÂ­do (primeros 800 chars): %s", (texto or "")[:800])

            if not texto or not texto.strip():
                try:
                    kb.save_documents()
                except Exception as e:
                    current_app.logger.exception("Error al crear index.json: %s", e)
                flash("Ã¢Å¡ Ã¯Â¸Â No se pudo extraer texto del archivo (ver logs).", "warning")
            else:
                doc_id = str(uuid.uuid4())
                meta = {
                    "filename": filename,
                    "uploaded_by": user_id,
                    "uploaded_by_role": user.role,
                    "uploaded_by_name": f"{user.first_name} {user.last_name}",
                    "uploaded_at": datetime.utcnow().isoformat(),
                    "visibility": "institucional" if user.role in ['profesor', 'admin'] else "personal"
                }
                try:
                    kb.add_document(doc_id, texto, meta=meta)
                    flash(flash_msg, "success")
                except Exception as e:
                    logger.exception("Error guardando documento en la KB: %s", e)
                    flash("Ã¢Å¡ Ã¯Â¸Â Error al indexar el documento en la base de conocimiento.", "error")
                    
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

# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ CHAT PRINCIPAL Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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
    files = File.query.filter_by(session_id=session_id)\
                      .order_by(File.uploaded_at).all()
    
    # Ã°Å¸â€Â¥ NUEVO: Capturar el initial_prompt de los parÃƒÂ¡metros URL
    initial_prompt = request.args.get('initial_prompt', '')
    
    return render_template(
        'chat_session.html',
        session=sess,
        messages=messages,
        files=files,
        selected_session_id=session_id,
        user_name=user.first_name,
        full_name=full_name,
        initial_prompt=initial_prompt  # Ã°Å¸â€Â¥ Pasar el prompt inicial al template
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
    return jsonify({'error': 'nombre invÃƒÂ¡lido'}), 400

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


# 3. Modificar stream_chat para usar la nueva funciÃƒÂ³n
@routes.route("/stream_chat/<int:session_id>", methods=["POST"])
def stream_chat(session_id: int) -> Response:
    # ... código de autenticación existente ...
    
    if 'user_id' not in login_session:
        return ("no autorizado", 401)

    sess = ChatSession.query.get_or_404(session_id)
    if sess.user_id != login_session['user_id']:
        return ("forbidden", 403)

    user_id = login_session['user_id']
    prompt = (request.form.get("prompt") or "").strip()
    if not prompt:
        return ("Empty prompt", 400)

    # Guardar mensaje del usuario
    user_message = ChatMessage(
        session_id=session_id,
        sender="user",
        text=strip_think_all(prompt),
        timestamp=datetime.utcnow()
    )
    db.session.add(user_message)
    db.session.commit()

    # Crear mensaje del asistente vacío
    assistant_message = ChatMessage(
        session_id=session_id,
        sender="assistant",
        text="",
        timestamp=datetime.utcnow()
    )
    db.session.add(assistant_message)
    db.session.commit()
    assistant_msg_id = assistant_message.id

    # Recuperar historial
    history = ChatMessage.query.filter_by(session_id=session_id).order_by(ChatMessage.timestamp).all()

    def event_stream() -> Generator[str, None, None]:
        accumulated_text = ""
        think_stripper = ThinkStripper()
        
        try:
            # 🔥 NUEVO: Construir system prompt con TODO el conocimiento y análisis pedagógico
            system_prompt = construir_system_prompt_con_conocimiento(user_id, history)
            
            # Construir prompt con historial
            model_prompt_parts = [system_prompt]  # Empezar con el system prompt completo
            
            # Agregar historial de conversación
            model_prompt_parts.append("\n=== HISTORIAL DE CONVERSACIÓN ===")
            for msg in history[:-1]:  # Excluir el último mensaje (que es el actual)
                if msg.sender == "user":
                    model_prompt_parts.append(f"Usuario: {msg.text}")
                else:
                    model_prompt_parts.append(f"Asistente: {msg.text}")
            
            # Agregar la pregunta actual
            model_prompt_parts.append(f"\nUsuario: {prompt}")
            model_prompt_parts.append("\nAsistente: ")
            
            model_prompt = "\n".join(model_prompt_parts)
            
            # Llamar al modelo
            try:
                # 🔥 MODIFICAR: Usar el prompt completo con sistema
                from app.ollama_stream import GroqClientWrapper
                client = GroqClientWrapper()
                
                # Llamada directa al client con system prompt incluido
                resp = client.client.chat.completions.create(
                    model="openai/gpt-oss-120b",  # o el modelo que uses
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": f"Historial:\n{chr(10).join([f'{msg.sender}: {msg.text}' for msg in history[:-1]])}\n\nPregunta actual: {prompt}"}
                    ],
                    max_tokens=8192,
                    temperature=0.7,
                    stream=True  # 🔥 IMPORTANTE: Habilitar streaming
                )
                
                # 🔥 NUEVO: Procesar respuesta streaming
                for chunk in resp:
                    if chunk.choices[0].delta.content:
                        content = chunk.choices[0].delta.content
                        cleaned = think_stripper.feed(content)
                        if cleaned:
                            accumulated_text += cleaned
                            
                            # Actualizar DB
                            try:
                                with current_app.app_context():
                                    msg_to_update = ChatMessage.query.get(assistant_msg_id)
                                    if msg_to_update:
                                        msg_to_update.text = _sanitize_persist(accumulated_text)
                                        db.session.commit()
                            except Exception as e:
                                logger.warning(f"Error updating message in DB: {e}")
                            
                            yield _sse_json_event({"chunk": cleaned})
                
            except Exception as e:
                logger.exception("LLM call failed: %s", e)
                error_msg = "Lo siento, el servicio de IA no está disponible en este momento."
                yield _sse_json_event({"chunk": error_msg})
                accumulated_text = error_msg
                return

        except GeneratorExit:
            logger.info("SSE client disconnected for session %s", session_id)
        except Exception as e:
            logger.exception("Unexpected error in stream_chat: %s", e)
            try:
                yield _sse_json_event({"error": "Internal server error"})
            except Exception:
                pass
        finally:
            # Guardar resultado final
            if accumulated_text:
                try:
                    think_stripper.finalize()
                    with current_app.app_context():
                        msg_to_update = ChatMessage.query.get(assistant_msg_id)
                        if msg_to_update:
                            final_text = _sanitize_persist(accumulated_text)
                            msg_to_update.text = final_text
                            msg_to_update.timestamp = datetime.utcnow()
                            db.session.commit()
                            logger.info(f"Final message saved to DB: {len(final_text)} chars")
                except Exception as e:
                    logger.error(f"Error saving final message to DB: {e}")

    response = Response(
        stream_with_context(event_stream()), 
        content_type="text/event-stream; charset=utf-8"
    )
    
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['Connection'] = 'keep-alive'
    response.headers['X-Accel-Buffering'] = 'no'

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
