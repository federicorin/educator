import os, re, uuid, logging, secrets, json, io
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from flask import send_file
from flask import Blueprint, request, session as login_session, redirect, url_for, render_template, flash, jsonify, current_app, send_from_directory, session, Response, stream_with_context, request, current_app
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv
from datetime import datetime, timedelta
from sqlalchemy import and_, or_
from typing import Generator, List, Dict
from .email_utils import send_invitation_email, send_password_reset_email
from .knowledge_base import KnowledgeBase
from .file_reader import procesar_archivo
from .ollama_stream import strip_think_all, construir_system_prompt_con_conocimiento, ThinkStripper
from .models import db, Usuario, ChatIA, MensajeChatIA, ArchivoMateria, InviteToken, RolUsuario, Institucion, TipoTarea, PatologiaAlumno, profesor_curso_materia, alumno_patologia, Curso, Materia, Tarea, RespuestaTarea, SesionAprendiendoPreguntar, AnalyticaComprension, AlertaContenidoSensible
load_dotenv()
routes = Blueprint('routes', __name__)
bp = Blueprint("chat", __name__)
logger = logging.getLogger(__name__)



#======================================
#               UTILS
#======================================    
def get_institution_statistics(institution_id):
    """
    Función helper para obtener todas las estadísticas de una institución
    """
    # Obtener todos los cursos de la institución
    cursos_ids = db.session.query(Curso.id).filter(
        Curso.institucion_id == institution_id
    ).subquery()
    
    # Contar usuarios por rol
    stats = {
        'profesores': 0,
        'tutores': 0, 
        'alumnos': 0,
        'padres': 0
    }
    
    # Profesores (a través de materias)
    stats['profesores'] = db.session.query(Usuario.id).distinct().join(
        profesor_curso_materia, Usuario.id == profesor_curso_materia.c.profesor_id
    ).join(
        Curso, profesor_curso_materia.c.curso_id == Curso.id
    ).filter(
        Curso.institucion_id == institution_id,
        Usuario.activo == True,
        Usuario.rol == RolUsuario.PROFESOR
    ).count()
    
    # Tutores
    stats['tutores'] = Usuario.query.join(
        Curso, Usuario.id == Curso.tutor_id
    ).filter(
        Curso.institucion_id == institution_id,
        Usuario.activo == True,
        Usuario.rol == RolUsuario.TUTOR
    ).count()
    
    # Alumnos
    stats['alumnos'] = Usuario.query.join(
        Curso, Usuario.curso_id == Curso.id
    ).filter(
        Curso.institucion_id == institution_id,
        Usuario.activo == True,
        Usuario.rol == RolUsuario.ALUMNO
    ).count()
    
    # Padres (más complejo - necesitamos encontrar padres de alumnos de esta institución)
    # Subconsulta para obtener IDs de alumnos de la institución
    alumnos_ids = db.session.query(Usuario.id).join(
        Curso, Usuario.curso_id == Curso.id
    ).filter(
        Curso.institucion_id == institution_id,
        Usuario.rol == RolUsuario.ALUMNO
    ).subquery()
    
    # Contar padres únicos
    padres_ids = set()
    
    # Padres como 'padre'
    padres_como_padre = db.session.query(Usuario.padre_id).filter(
        Usuario.id.in_(alumnos_ids),
        Usuario.padre_id.isnot(None)
    ).all()
    
    # Madres como 'madre'  
    madres_como_madre = db.session.query(Usuario.madre_id).filter(
        Usuario.id.in_(alumnos_ids),
        Usuario.madre_id.isnot(None)
    ).all()
    
    for padre_id, in padres_como_padre:
        if padre_id:
            padres_ids.add(padre_id)
            
    for madre_id, in madres_como_madre:
        if madre_id:
            padres_ids.add(madre_id)
    
    stats['padres'] = len(padres_ids)
    
    return stats

def get_recent_activities(institution_id, limit=10):
    """
    Obtiene las actividades recientes de una institución
    """
    actividades = []
    hace_30_dias = datetime.now() - timedelta(days=30)
    
    # Nuevos usuarios (alumnos de cursos de esta institución)
    nuevos_alumnos = Usuario.query.join(
        Curso, Usuario.curso_id == Curso.id
    ).filter(
        Curso.institucion_id == institution_id,
        Usuario.fecha_creacion >= hace_30_dias,
        Usuario.activo == True,
        Usuario.rol == RolUsuario.ALUMNO
    ).order_by(Usuario.fecha_creacion.desc()).limit(5).all()
    
    for alumno in nuevos_alumnos:
        actividades.append({
            'tipo': 'alumno_nuevo',
            'icono': 'fa-user-plus',
            'titulo': f'Nuevo alumno: {alumno.nombre} {alumno.apellido}',
            'descripcion': f'Se registró en el curso {alumno.curso.nombre if alumno.curso else "Sin asignar"}',
            'fecha': alumno.fecha_creacion
        })
    
    # Nuevos profesores (a través de asignaciones a materias)
    nuevos_profesores = db.session.query(Usuario).distinct().join(
        profesor_curso_materia, Usuario.id == profesor_curso_materia.c.profesor_id
    ).join(
        Curso, profesor_curso_materia.c.curso_id == Curso.id  
    ).filter(
        Curso.institucion_id == institution_id,
        Usuario.fecha_creacion >= hace_30_dias,
        Usuario.activo == True,
        Usuario.rol == RolUsuario.PROFESOR
    ).order_by(Usuario.fecha_creacion.desc()).limit(3).all()
    
    for profesor in nuevos_profesores:
        actividades.append({
            'tipo': 'profesor_nuevo',
            'icono': 'fa-chalkboard-teacher',
            'titulo': f'Nuevo profesor: {profesor.nombre} {profesor.apellido}',
            'descripcion': 'Se unió al equipo docente',
            'fecha': profesor.fecha_creacion
        })
    
    # Nuevos cursos
    nuevos_cursos = Curso.query.filter(
        Curso.institucion_id == institution_id,
        Curso.fecha_creacion >= hace_30_dias
    ).order_by(Curso.fecha_creacion.desc()).limit(3).all()
    
    for curso in nuevos_cursos:
        actividades.append({
            'tipo': 'curso_nuevo',
            'icono': 'fa-graduation-cap',
            'titulo': f'Nuevo curso: {curso.nombre}',
            'descripcion': f'Nivel: {curso.nivel or "No especificado"}',
            'fecha': curso.fecha_creacion
        })
    
    # Archivos subidos recientemente
    nuevos_archivos = ArchivoMateria.query.join(Materia).join(Curso).filter(
        Curso.institucion_id == institution_id,
        ArchivoMateria.fecha_subida >= hace_30_dias
    ).order_by(ArchivoMateria.fecha_subida.desc()).limit(3).all()
    
    for archivo in nuevos_archivos:
        profesor = Usuario.query.get(archivo.profesor_id)
        actividades.append({
            'tipo': 'archivo_subido',
            'icono': 'fa-file-upload',
            'titulo': f'Material subido: {archivo.nombre_tema}',
            'descripcion': f'Por {profesor.nombre if profesor else "Usuario desconocido"} en {archivo.materia.nombre}',
            'fecha': archivo.fecha_subida
        })
    
    # Ordenar por fecha y limitar resultados
    actividades.sort(key=lambda x: x['fecha'], reverse=True)
    return actividades[:limit]

def get_system_alerts(institution_id):
    """
    Genera alertas del sistema para la institución
    """
    alertas = []
    
    # Cursos sin tutor
    cursos_sin_tutor = Curso.query.filter(
        Curso.institucion_id == institution_id,
        Curso.tutor_id.is_(None)
    ).count()
    
    if cursos_sin_tutor > 0:
        alertas.append({
            'tipo': 'warning',
            'mensaje': f'Hay {cursos_sin_tutor} curso(s) sin tutor asignado',
            'accion': 'Gestionar Cursos'
        })
    
    # Alumnos sin curso asignado
    # Esto requiere una consulta más compleja dependiendo de cómo manejes la relación
    
    # Alertas de contenido sensible
    alertas_contenido = AlertaContenidoSensible.query.join(
        ChatIA
    ).join(Usuario).join(Curso).filter(
        Curso.institucion_id == institution_id,
        AlertaContenidoSensible.revisada == False
    ).count()
    
    if alertas_contenido > 0:
        alertas.append({
            'tipo': 'danger',
            'mensaje': f'Hay {alertas_contenido} alerta(s) de contenido sensible sin revisar',
            'accion': 'Ver Alertas'
        })
    
    return alertas
    
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

def create_admin_user():
    admin_email = os.getenv("ADMIN_EMAIL")
    admin_password = os.getenv("ADMIN_PASSWORD")

    if not admin_email or not admin_password:
        print("ADMIN_EMAIL o ADMIN_PASSWORD no están definidos en .env")
        return

    existing_admin = Usuario.query.filter_by(email=admin_email).first()
    if not existing_admin:
        from datetime import date
        admin_user = Usuario(
            nombre="Admin",           # ✅ Usar 'nombre' en lugar de 'first_name'
            apellido="Principal",     # ✅ Usar 'apellido' en lugar de 'last_name'
            email=admin_email,
            fecha_nacimiento=date(1990, 1, 1),  # ✅ Campo requerido
            rol=RolUsuario.ADMIN,     # ✅ Usar enum
            password_hash=generate_password_hash(admin_password)
        )
        db.session.add(admin_user)
        db.session.commit()
        print("✅ Usuario administrador creado")
    else:
        print("⚹️ Usuario administrador ya existe")

def is_admin(user):
    return user.role == 'admin'

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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





#======================================
#         CONTEXTO DE RUTAS
#======================================
@routes.context_processor
def inject_user_globals():
    if 'user_id' in login_session:
        user = Usuario.query.get(login_session['user_id'])
        # ✅ Verificar que el usuario existe antes de acceder a sus propiedades
        if user:
            sessions = ChatIA.query\
                        .filter_by(usuario_id=user.id)\
                        .order_by(ChatIA.fecha_ultimo_mensaje.desc())\
                        .all()
            return {
                'sessions': sessions,
                'user_name': user.nombre,  # ✅ Usar 'nombre'
                'user': user
            }
    # ✅ Retornar diccionario vacío si no hay usuario o el usuario no existe
    return {}





#======================================
#      INVITACION A LA PLATAFORMA
#======================================
@routes.route('/send_invitation', methods=['POST'])
def send_invitation():
    user_id = session.get('user_id')
    user = db.session.get(Usuario, user_id)
    if not user or user.rol != RolUsuario.ADMIN:
        return redirect(url_for('routes.login'))

    email = request.form['email']
    nombre = request.form['nombre']
    apellido = request.form['apellido']
    role = request.form['role']

    token = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + timedelta(days=2)

    if isinstance(role, str):
        role_enum = RolUsuario(role)
    else:
        role_enum = role

    invitation = InviteToken(
        email=email, 
        token=token, 
        rol=role_enum,
        nombre=nombre,
        apellido=apellido,
        fecha_expiracion=expires
    )
    db.session.add(invitation)
    db.session.commit()

    link = url_for('routes.accept_invitation', token=token, _external=True)

    send_invitation_email(
        to_email=email,
        first_name=nombre,
        invite_url=link,
        expiration="48 horas"
    )

    flash("Invitación enviada con éxito", "success")
    return redirect(url_for('routes.admin_panel'))

@routes.route('/registro/aceptar', methods=['GET', 'POST'])
def accept_invitation():
    token_str = request.args.get('token')
    token_obj = InviteToken.query.filter_by(token=token_str).first()

    if not token_obj or not token_obj.is_valid():
        flash("Invitación no válida o expirada.", "error")
        return redirect(url_for('routes.login'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form.get('confirm_password', '')
        
        # Validar que las contraseñas coincidan
        if password != confirm_password:
            flash("Las contraseñas no coinciden", "error")
            return render_template("register_from_invite.html", invitation=token_obj)
        
        # Validar longitud mínima de contraseña
        if len(password) < 6:
            flash("La contraseña debe tener al menos 6 caracteres", "error")
            return render_template("register_from_invite.html", invitation=token_obj)
        
        try:
            # Verificar si ya existe un usuario con este email
            existing_user = Usuario.query.filter_by(email=token_obj.email).first()
            
            if existing_user:
                # Si el usuario ya existe, solo actualizamos la contraseña y activamos
                existing_user.set_password(password)
                existing_user.activo = True
                
                # Marcar el email como confirmado si no lo estaba
                if not existing_user.is_email_confirmed:
                    existing_user.email_confirmed_at = datetime.utcnow()
                
                # Actualizar datos desde la invitación si es necesario
                if not existing_user.nombre or existing_user.nombre != token_obj.nombre:
                    existing_user.nombre = token_obj.nombre
                if not existing_user.apellido or existing_user.apellido != token_obj.apellido:
                    existing_user.apellido = token_obj.apellido
                
                db.session.delete(token_obj)
                db.session.commit()
                
                flash("Contraseña establecida exitosamente", "success")
                return redirect(url_for('routes.login'))
            else:
                # Crear nuevo usuario con datos de la invitación
                from datetime import date
                
                # Obtener datos adicionales si existen
                datos_adicionales = token_obj.get_datos_adicionales() if hasattr(token_obj, 'get_datos_adicionales') else {}
                
                # Fecha de nacimiento: usar la de datos adicionales o una por defecto
                fecha_nacimiento = date(2000, 1, 1)  # Por defecto
                if datos_adicionales.get('fecha_nacimiento'):
                    try:
                        fecha_nacimiento = datetime.strptime(datos_adicionales['fecha_nacimiento'], '%Y-%m-%d').date()
                    except (ValueError, TypeError):
                        pass
                
                new_user = Usuario(
                    email=token_obj.email,
                    nombre=token_obj.nombre,
                    apellido=token_obj.apellido,
                    rol=token_obj.rol,
                    fecha_nacimiento=fecha_nacimiento,
                    activo=True,
                    email_confirmed_at=datetime.utcnow()
                )
                new_user.set_password(password)
                
                # Configuraciones adicionales según el rol
                if token_obj.rol == RolUsuario.ALUMNO and datos_adicionales.get('curso_id'):
                    new_user.curso_id = datos_adicionales['curso_id']
                
                db.session.add(new_user)
                db.session.flush()  # Para obtener el ID del usuario
                
                # Si es alumno y tiene patologías, agregarlas
                if (token_obj.rol == RolUsuario.ALUMNO and 
                    datos_adicionales.get('patologias') and 
                    hasattr(new_user, 'agregar_patologia')):
                    try:
                        for patologia in datos_adicionales['patologias']:
                            new_user.agregar_patologia(patologia)
                    except Exception as e:
                        logger.error(f"Error agregando patologías: {e}")
                
                # Si es tutor y tiene curso asignado, actualizarlo
                if (token_obj.rol == RolUsuario.TUTOR and 
                    datos_adicionales.get('curso_id')):
                    try:
                        curso = Curso.query.get(datos_adicionales['curso_id'])
                        if curso and not curso.tutor_id:
                            curso.tutor_id = new_user.id
                    except Exception as e:
                        logger.error(f"Error asignando tutor a curso: {e}")
                
                db.session.delete(token_obj)
                db.session.commit()
                
                flash("Cuenta creada exitosamente", "success")
                return redirect(url_for('routes.login'))
                
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error procesando invitación: {e}")
            flash("Error al procesar la invitación. Intente nuevamente.", "error")
            return render_template("register_from_invite.html", invitation=token_obj)

    # GET request - mostrar formulario con datos de la invitación
    return render_template("register_from_invite.html", invitation=token_obj)





#======================================
#               LOGIN
#======================================
@routes.route('/')
def root():
    return redirect(url_for('routes.login'))

@routes.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        user = Usuario.query.filter_by(email=email).first()

        if not user:
            flash("Usuario no encontrado", "error")
            return render_template('login.html')

        # Validar que el rol enviado coincide con el rol del usuario
        if role == 'student' and user.rol not in [RolUsuario.ALUMNO, RolUsuario.PADRE, RolUsuario.MADRE]:  # ✅ Usar enum
            flash("Este email no pertenece a un alumno", "error")
            return render_template('login.html')
        elif role == 'staff' and user.rol not in [RolUsuario.ADMIN, RolUsuario.DIRECTOR, RolUsuario.PROFESOR, RolUsuario.TUTOR]:  # ✅ Usar enum
            flash("Este email no pertenece a un profesor o admin", "error")
            return render_template('login.html')

        # Validar contraseña
        if user.check_password(password):
            login_session['user_id'] = user.id
            login_session['user_name'] = user.nombre

            # Redirigir a panel según rol
            if user.rol == RolUsuario.ADMIN:
                return redirect(url_for('routes.admin_panel'))
            elif user.rol == RolUsuario.DIRECTOR:
                return redirect(url_for('routes.director_panel', institution_id=user.institucion_dirigida.id))
            elif user.rol == RolUsuario.PROFESOR:
                return redirect(url_for('routes.chat_index'))
            elif user.rol == RolUsuario.ALUMNO:
                return redirect(url_for('routes.chat_index'))
        else:
            flash("Contraseña incorrecta", "error")

    return render_template('login.html')

@routes.route("/logout", methods=["POST"])
def logout():
    login_session.clear()
    return redirect(url_for("routes.login"))

@routes.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        # Buscar usuario por email
        user = Usuario.query.filter_by(email=email).first()
        
        if user:
            # Generar token seguro
            reset_token = secrets.token_urlsafe(32)
            
            # Guardar token en la base de datos (necesitarás agregar estos campos al modelo Usuario)
            user.reset_password_token = reset_token
            user.reset_password_expires = datetime.utcnow() + timedelta(hours=1)  # Token expira en 1 hora
            
            try:
                db.session.commit()
                
                # Construir URL de reseteo
                reset_url = url_for('routes.reset_password', token=reset_token, _external=True)
                
                # Enviar email
                send_password_reset_email(
                    to_email=user.email,
                    first_name=user.nombre,
                    reset_url=reset_url,
                    expiration="1 hora"
                )
                
                flash("Se ha enviado un enlace de recuperación a tu email", "success")
                
            except Exception as e:
                db.session.rollback()
                print(f"Error enviando email de reseteo: {e}")
                flash("Hubo un problema enviando el email. Intenta más tarde.", "error")
        else:
            # Por seguridad, mostramos el mismo mensaje aunque el usuario no exista
            flash("Se ha enviado un enlace de recuperación a tu email", "success")
        
        return redirect(url_for('routes.login'))
    
    return render_template('forgot_password.html')


@routes.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Buscar usuario por token
    user = Usuario.query.filter_by(reset_password_token=token).first()
    
    # Verificar que el token existe y no ha expirado
    if not user or not user.reset_password_expires or user.reset_password_expires < datetime.utcnow():
        flash("El enlace de recuperación ha expirado o no es válido", "error")
        return redirect(url_for('routes.forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validar que las contraseñas coinciden
        if new_password != confirm_password:
            flash("Las contraseñas no coinciden", "error")
            return render_template('reset_password.html', token=token)
        
        # Validar longitud mínima
        if len(new_password) < 6:
            flash("La contraseña debe tener al menos 6 caracteres", "error")
            return render_template('reset_password.html', token=token)
        
        # Actualizar contraseña
        user.set_password(new_password)  # Asume que tienes este método en tu modelo
        user.reset_password_token = None
        user.reset_password_expires = None
        
        try:
            db.session.commit()
            flash("Tu contraseña ha sido actualizada exitosamente", "success")
            return redirect(url_for('routes.login'))
        except Exception as e:
            db.session.rollback()
            print(f"Error actualizando contraseña: {e}")
            flash("Hubo un problema actualizando tu contraseña", "error")
    
    return render_template('reset_password.html', token=token)




#======================================
#                ADMIN
#======================================
@routes.route('/admin/panel')
def admin_panel():
    if 'user_id' not in login_session:
        return redirect(url_for('routes.login'))

    user = Usuario.query.get(login_session['user_id'])
    if user.rol != RolUsuario.ADMIN:  # ✅ Usar enum
        flash("No autorizado", "error")
        return redirect(url_for('routes.chat_index'))

    return render_template('admin_panel.html')

@routes.route('/create_institution', methods=['POST'])
def create_institution():
    """Nueva ruta para crear instituciones con director"""
    user_id = session.get('user_id')
    user = db.session.get(Usuario, user_id)
    if not user or user.rol != RolUsuario.ADMIN:
        return redirect(url_for('routes.login'))

    # Datos de la institución
    nombre_institucion = request.form['nombre_institucion']
    
    # Datos del director
    email_director = request.form['email_director']
    nombre_director = request.form['nombre_director']
    apellido_director = request.form['apellido_director']
    fecha_nacimiento_str = request.form['fecha_nacimiento_director']
    
    # Manejo de logos (opcional)
    logo_grande = None
    logo_pequeno = None
    
    if 'logo_grande' in request.files and request.files['logo_grande'].filename:
        logo_file = request.files['logo_grande']
        if allowed_file(logo_file.filename):
            filename = secure_filename(f"logo_grande_{secrets.token_hex(8)}_{logo_file.filename}")
            logos_path = os.path.join(current_app.config.get('UPLOAD_ROOT', 'uploads'), 'logos')
            os.makedirs(logos_path, exist_ok=True)
            logo_path = os.path.join(logos_path, filename)
            logo_file.save(logo_path)
            logo_grande = filename
    
    if 'logo_pequeno' in request.files and request.files['logo_pequeno'].filename:
        logo_file = request.files['logo_pequeno']
        if allowed_file(logo_file.filename):
            filename = secure_filename(f"logo_pequeno_{secrets.token_hex(8)}_{logo_file.filename}")
            logos_path = os.path.join(current_app.config.get('UPLOAD_ROOT', 'uploads'), 'logos')
            os.makedirs(logos_path, exist_ok=True)
            logo_path = os.path.join(logos_path, filename)
            logo_file.save(logo_path)
            logo_pequeno = filename
    
    try:
        # Convertir fecha de nacimiento
        from datetime import datetime, date
        if fecha_nacimiento_str:
            fecha_nacimiento = datetime.strptime(fecha_nacimiento_str, '%Y-%m-%d').date()
        else:
            fecha_nacimiento = date(1980, 1, 1)  # Fecha por defecto

        # Verificar que el email no exista
        existing_user = Usuario.query.filter_by(email=email_director).first()
        if existing_user:
            flash("Ya existe un usuario con ese email", "error")
            return redirect(url_for('routes.admin_panel'))

        # Generar token para invitación
        token = secrets.token_urlsafe(32)
        expires = datetime.utcnow() + timedelta(days=2)

        # Crear el usuario director SIN contraseña (se establecerá cuando acepte la invitación)
        director = Usuario(
            email=email_director,
            nombre=nombre_director,
            apellido=apellido_director,
            fecha_nacimiento=fecha_nacimiento,
            rol=RolUsuario.DIRECTOR,
            # NO establecer password_hash aquí - será None hasta que acepte la invitación
            activo=False  # Marcar como inactivo hasta que acepte
        )
        db.session.add(director)
        db.session.flush()  # Para obtener el ID del director

        # Crear la institución
        institucion = Institucion(
            nombre=nombre_institucion,
            director_id=director.id,
            logo_grande=logo_grande,
            logo_pequeno=logo_pequeno
        )
        db.session.add(institucion)

        # Crear token de invitación
        invitation = InviteToken(
            email=email_director,
            token=token,
            rol=RolUsuario.DIRECTOR,
            nombre=nombre_director,
            apellido=apellido_director,
            fecha_expiracion=expires
        )
        db.session.add(invitation)
        
        db.session.commit()

        # Enviar email usando la función existente
        link = url_for('routes.accept_invitation', token=token, _external=True)
        
        send_invitation_email(
            to_email=email_director,
            first_name=nombre_director,
            invite_url=link,
            expiration="48 horas"
        )

        print(f"[OK] Invitación enviada a {email_director}")
        flash(f"Institución '{nombre_institucion}' creada exitosamente. Se envió email al director.", "success")
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creando institución: {e}")
        flash("Error al crear la institución. Revise los datos e intente nuevamente.", "error")

    return redirect(url_for('routes.admin_panel'))


@routes.route('/api/institutions', methods=['GET'])
def get_institutions():
    """API para obtener todas las instituciones con datos del director"""
    if 'user_id' not in login_session:
        return jsonify({'error': 'no autorizado'}), 401

    user = Usuario.query.get(login_session['user_id'])
    if user.rol != RolUsuario.ADMIN:
        return jsonify({'error': 'no autorizado'}), 403

    try:
        # Obtener todas las instituciones con sus directores
        instituciones = db.session.query(Institucion).join(Usuario).all()
        
        result = []
        for inst in instituciones:
            director = inst.director
            result.append({
                'id': inst.id,
                'nombre': inst.nombre,
                'logo_grande': inst.logo_grande,
                'logo_pequeno': inst.logo_pequeno,
                'fecha_creacion': inst.fecha_creacion.isoformat(),
                'director': {
                    'id': director.id,
                    'nombre': director.nombre,
                    'apellido': director.apellido,
                    'email': director.email,
                    'activo': director.activo,
                    'email_confirmado': director.is_email_confirmed
                },
                'valores_institucionales': inst.valores_institucionales,
                'metodologia_pedagogica': inst.metodologia_pedagogica,
                'configuracion_ia': inst.configuracion_ia
            })
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error obteniendo instituciones: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@routes.route('/uploads/logos/<filename>')
def serve_logo(filename):
    """Servir archivos de logos"""
    logos_path = os.path.join(current_app.config.get('UPLOAD_ROOT', 'uploads'), 'logos')
    return send_from_directory(logos_path, filename)

@routes.route('/api/institution/<int:institution_id>', methods=['GET'])
def get_institution_details(institution_id):
    """Obtener detalles completos de una institución"""
    if 'user_id' not in login_session:
        return jsonify({'error': 'no autorizado'}), 401

    user = Usuario.query.get(login_session['user_id'])
    if user.rol != RolUsuario.ADMIN:
        return jsonify({'error': 'no autorizado'}), 403

    try:
        # Obtener institución con director
        institucion = db.session.query(Institucion).filter_by(id=institution_id).first()
        if not institucion:
            return jsonify({'error': 'Institución no encontrada'}), 404

        director = institucion.director
        usuarios_institucion = []
        usuarios_institucion = [director]

        result = {
            'id': institucion.id,
            'nombre': institucion.nombre,
            'logo_grande': institucion.logo_grande,
            'logo_pequeno': institucion.logo_pequeno,
            'fecha_creacion': institucion.fecha_creacion.isoformat(),
            'valores_institucionales': institucion.valores_institucionales,
            'metodologia_pedagogica': institucion.metodologia_pedagogica,
            'configuracion_ia': institucion.configuracion_ia,
            'director': {
                'id': director.id,
                'nombre': director.nombre,
                'apellido': director.apellido,
                'email': director.email,
                'fecha_nacimiento': director.fecha_nacimiento.isoformat() if director.fecha_nacimiento else None,
                'rol': director.rol.value,
                'activo': director.activo,
                'email_confirmado': director.is_email_confirmed,
                'fecha_creacion': director.fecha_creacion.isoformat() if hasattr(director, 'fecha_creacion') else None
            },
            'usuarios': []
        }

        # Agregar todos los usuarios de la institución
        for usuario in usuarios_institucion:
            result['usuarios'].append({
                'id': usuario.id,
                'nombre': usuario.nombre,
                'apellido': usuario.apellido,
                'email': usuario.email,
                'rol': usuario.rol.value,
                'activo': usuario.activo,
                'email_confirmado': usuario.is_email_confirmed,
                'fecha_nacimiento': usuario.fecha_nacimiento.isoformat() if usuario.fecha_nacimiento else None
            })

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error obteniendo detalles de institución: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@routes.route('/api/institution/<int:institution_id>/director', methods=['PUT'])
def update_director(institution_id):
    """Actualizar datos del director de una institución"""
    if 'user_id' not in login_session:
        return jsonify({'error': 'no autorizado'}), 401

    user = Usuario.query.get(login_session['user_id'])
    if user.rol != RolUsuario.ADMIN:
        return jsonify({'error': 'no autorizado'}), 403

    try:
        # Obtener institución
        institucion = Institucion.query.get(institution_id)
        if not institucion:
            return jsonify({'error': 'Institución no encontrada'}), 404

        director = institucion.director
        
        # Obtener datos del request
        data = request.get_json()
        
        # Validar email único (excepto el actual)
        if 'email' in data and data['email'] != director.email:
            existing_user = Usuario.query.filter_by(email=data['email']).first()
            if existing_user:
                return jsonify({'error': 'Ya existe un usuario con ese email'}), 400

        # Actualizar campos
        if 'nombre' in data:
            director.nombre = data['nombre'].strip()
        
        if 'apellido' in data:
            director.apellido = data['apellido'].strip()
        
        if 'email' in data:
            director.email = data['email'].strip()
        
        if 'fecha_nacimiento' in data and data['fecha_nacimiento']:
            from datetime import datetime
            director.fecha_nacimiento = datetime.strptime(data['fecha_nacimiento'], '%Y-%m-%d').date()
        
        if 'password' in data and data['password'].strip():
            director.set_password(data['password'])
        
        # Actualizar timestamp
        director.fecha_actualizacion = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Director actualizado exitosamente',
            'director': {
                'id': director.id,
                'nombre': director.nombre,
                'apellido': director.apellido,
                'email': director.email,
                'fecha_nacimiento': director.fecha_nacimiento.isoformat() if director.fecha_nacimiento else None
            }
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error actualizando director: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500





#======================================
#            RUTAS DEL DIRECTOR
#======================================
@routes.route('/institution/<int:institution_id>/director')
def director_panel(institution_id):
    """Panel principal del director"""
    if 'user_id' not in login_session:
        return redirect(url_for('routes.login'))
     
    user = Usuario.query.get(login_session['user_id'])
    if user.rol != RolUsuario.DIRECTOR:
        flash("No autorizado", "error")
        return redirect(url_for('routes.chat_index'))
     
    # Verificar que el director pertenece a esta institución
    institucion = Institucion.query.get_or_404(institution_id)
    if institucion.director_id != user.id:
        flash("No autorizado para esta institución", "error")
        return redirect(url_for('routes.chat_index'))
    
    # === ESTADÍSTICAS BÁSICAS SIN CONSULTAS COMPLEJAS ===
    
    # 1. Cursos activos
    total_cursos_activos = Curso.query.filter(
        Curso.institucion_id == institution_id
    ).count()
    
    # 2. Materias activas
    total_materias_activas = db.session.query(Materia).join(Curso).filter(
        Curso.institucion_id == institution_id
    ).count()
    
    # 3. Alumnos (usuarios con curso_id en cursos de esta institución)
    cursos_ids = [c.id for c in Curso.query.filter_by(institucion_id=institution_id).all()]
    total_alumnos = Usuario.query.filter(
        Usuario.rol == RolUsuario.ALUMNO,
        Usuario.activo == True,
        Usuario.curso_id.in_(cursos_ids)
    ).count() if cursos_ids else 0
    
    # 4. Profesores (simplificado - a través de materias)
    profesores_ids = set()
    for curso in Curso.query.filter_by(institucion_id=institution_id).all():
        for materia in curso.materias:
            for profesor in materia.profesores:
                if profesor.rol == RolUsuario.PROFESOR and profesor.activo:
                    profesores_ids.add(profesor.id)
    total_profesores = len(profesores_ids)
    
    # 5. Tutores (usuarios que son tutores de cursos de esta institución)
    total_tutores = Usuario.query.filter(
        Usuario.rol == RolUsuario.TUTOR,
        Usuario.activo == True,
        Usuario.id.in_(
            db.session.query(Curso.tutor_id).filter(
                Curso.institucion_id == institution_id,
                Curso.tutor_id.isnot(None)
            )
        )
    ).count()
    
    # 6. Padres (simplificado)
    padres_ids = set()
    for alumno in Usuario.query.filter(
        Usuario.rol == RolUsuario.ALUMNO,
        Usuario.curso_id.in_(cursos_ids)
    ).all():
        if alumno.padre_id:
            padres_ids.add(alumno.padre_id)
        if alumno.madre_id:
            padres_ids.add(alumno.madre_id)
    total_padres = len(padres_ids)
    
    total_usuarios_activos = total_profesores + total_tutores + total_alumnos + total_padres
    
    # 7. Interacciones IA (simplificado)
    inicio_mes = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    # Obtener IDs de usuarios de la institución
    usuarios_institucion_ids = []
    usuarios_institucion_ids.extend([a.id for a in Usuario.query.filter(
        Usuario.curso_id.in_(cursos_ids)
    ).all()])
    usuarios_institucion_ids.extend(list(profesores_ids))
    usuarios_institucion_ids.extend([t.id for t in Usuario.query.filter(
        Usuario.id.in_(
            db.session.query(Curso.tutor_id).filter(
                Curso.institucion_id == institution_id,
                Curso.tutor_id.isnot(None)
            )
        )
    ).all()])
    
    # Contar mensajes de IA de estos usuarios
    interacciones_ia_mes = 0
    if usuarios_institucion_ids:
        interacciones_ia_mes = MensajeChatIA.query.join(ChatIA).filter(
            ChatIA.usuario_id.in_(usuarios_institucion_ids),
            MensajeChatIA.fecha_envio >= inicio_mes
        ).count()
    
    # 8. Estado de configuración IA
    configuracion_ia_completa = bool(
        institucion.valores_institucionales and 
        institucion.metodologia_pedagogica
    )
    
    # === ACTIVIDADES RECIENTES (SIMPLIFICADAS) ===
    actividades_recientes = []
    hace_30_dias = datetime.now() - timedelta(days=30)
    
    # Nuevos alumnos
    nuevos_alumnos = Usuario.query.filter(
        Usuario.rol == RolUsuario.ALUMNO,
        Usuario.activo == True,
        Usuario.curso_id.in_(cursos_ids),
        Usuario.fecha_creacion >= hace_30_dias
    ).order_by(Usuario.fecha_creacion.desc()).limit(5).all() if cursos_ids else []
    
    for alumno in nuevos_alumnos:
        curso = Curso.query.get(alumno.curso_id) if alumno.curso_id else None
        actividades_recientes.append({
            'tipo': 'alumno_nuevo',
            'icono': 'fa-user-plus',
            'titulo': f'Nuevo alumno: {alumno.nombre} {alumno.apellido}',
            'descripcion': f'Se registró en el curso {curso.nombre if curso else "Sin asignar"}',
            'fecha': alumno.fecha_creacion
        })
    
    # Nuevos cursos
    nuevos_cursos = Curso.query.filter(
        Curso.institucion_id == institution_id,
        Curso.fecha_creacion >= hace_30_dias
    ).order_by(Curso.fecha_creacion.desc()).limit(3).all()
    
    for curso in nuevos_cursos:
        actividades_recientes.append({
            'tipo': 'curso_nuevo',
            'icono': 'fa-graduation-cap',
            'titulo': f'Nuevo curso: {curso.nombre}',
            'descripcion': f'Nivel: {curso.nivel or "No especificado"}',
            'fecha': curso.fecha_creacion
        })
    
    # Archivos subidos recientemente
    nuevos_archivos = db.session.query(ArchivoMateria).join(Materia).join(Curso).filter(
        Curso.institucion_id == institution_id,
        ArchivoMateria.fecha_subida >= hace_30_dias
    ).order_by(ArchivoMateria.fecha_subida.desc()).limit(3).all()
    
    for archivo in nuevos_archivos:
        profesor = Usuario.query.get(archivo.profesor_id)
        actividades_recientes.append({
            'tipo': 'archivo_subido',
            'icono': 'fa-file-upload',
            'titulo': f'Material subido: {archivo.nombre_tema}',
            'descripcion': f'Por {profesor.nombre if profesor else "Usuario desconocido"} en {archivo.materia.nombre}',
            'fecha': archivo.fecha_subida
        })
    
    # Ordenar actividades por fecha
    actividades_recientes.sort(key=lambda x: x['fecha'], reverse=True)
    actividades_recientes = actividades_recientes[:10]
    
    # === ALERTAS DEL SISTEMA ===
    alertas = []
    
    # Cursos sin tutor
    cursos_sin_tutor = Curso.query.filter(
        Curso.institucion_id == institution_id,
        Curso.tutor_id.is_(None)
    ).count()
    
    if cursos_sin_tutor > 0:
        alertas.append({
            'tipo': 'warning',
            'mensaje': f'Hay {cursos_sin_tutor} curso(s) sin tutor asignado',
            'accion': 'Gestionar Cursos'
        })
    
    # Configuración IA incompleta
    if not configuracion_ia_completa:
        alertas.append({
            'tipo': 'info',
            'mensaje': 'La configuración de IA no está completa',
            'accion': 'Configurar IA'
        })
    
    # Alertas de contenido sensible (simplificado)
    try:
        alertas_contenido = AlertaContenidoSensible.query.filter_by(revisada=False).count()
        if alertas_contenido > 0:
            alertas.append({
                'tipo': 'danger',
                'mensaje': f'Hay {alertas_contenido} alerta(s) de contenido sensible sin revisar',
                'accion': 'Ver Alertas'
            })
    except Exception:
        # Si hay problemas con la consulta, simplemente omitir esta alerta
        pass
    
    # === ESTADÍSTICAS DETALLADAS ===
    estadisticas_detalladas = {
        'usuarios_por_rol': {
            'profesores': total_profesores,
            'tutores': total_tutores,
            'alumnos': total_alumnos,
            'padres': total_padres
        },
        'cursos_y_materias': {
            'cursos': total_cursos_activos,
            'materias': total_materias_activas
        },
        'interacciones_ia': {
            'este_mes': interacciones_ia_mes,
            'promedio_diario': round(interacciones_ia_mes / max(datetime.now().day, 1), 1) if interacciones_ia_mes > 0 else 0
        }
    }
    
    return render_template('director_panel.html', 
                         institucion=institucion,
                         user_name=f"{user.nombre} {user.apellido}",
                         total_usuarios_activos=total_usuarios_activos,
                         total_cursos_activos=total_cursos_activos,
                         total_materias_activas=total_materias_activas,
                         interacciones_ia_mes=interacciones_ia_mes,
                         configuracion_ia_completa=configuracion_ia_completa,
                         actividades_recientes=actividades_recientes,
                         estadisticas_detalladas=estadisticas_detalladas,
                         alertas=alertas)

@routes.route('/institution/<int:institution_id>/director/config', methods=['GET', 'POST'])
def director_config(institution_id):
    """Configuración de valores institucionales y IA"""
    if 'user_id' not in login_session:
        return redirect(url_for('routes.login'))

    user = Usuario.query.get(login_session['user_id'])
    if user.rol != RolUsuario.DIRECTOR:
        flash("No autorizado", "error")
        return redirect(url_for('routes.chat_index'))

    institucion = Institucion.query.get_or_404(institution_id)
    if institucion.director_id != user.id:
        flash("No autorizado", "error")
        return redirect(url_for('routes.director_panel', institution_id=institution_id))

    if request.method == 'POST':
        try:
            # Actualizar valores institucionales
            institucion.valores_institucionales = request.form.get('valores_institucionales', '').strip()
            institucion.metodologia_pedagogica = request.form.get('metodologia_pedagogica', '').strip()
            
            # Configuración IA como JSON
            config_ia = {
                'tono': request.form.get('tono_ia', 'formal'),
                'enfoque_pedagogico': request.form.get('enfoque_pedagogico', 'tradicional'),
                'nivel_detalle': request.form.get('nivel_detalle', 'medio'),
                'usar_ejemplos': request.form.get('usar_ejemplos') == 'on',
                'instrucciones_especiales': request.form.get('instrucciones_especiales', '').strip()
            }
            institucion.configuracion_ia = json.dumps(config_ia)
            
            db.session.commit()
            flash("Configuración actualizada exitosamente", "success")
            return redirect(url_for('routes.director_config', institution_id=institution_id))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error actualizando configuración: {e}")
            flash("Error al actualizar configuración", "error")

    # Cargar configuración existente para el GET
    config_ia_actual = {}
    if institucion.configuracion_ia:
        try:
            config_ia_actual = json.loads(institucion.configuracion_ia)
        except (TypeError, json.JSONDecodeError):
            config_ia_actual = {}

    return render_template('director_config.html', 
                         institucion=institucion,
                         config_ia=config_ia_actual,
                         user_name=f"{user.nombre} {user.apellido}")

@routes.route('/institution/<int:institution_id>/director/users')
def director_users(institution_id):
    """Ver todos los usuarios de la institución"""
    if 'user_id' not in login_session:
        return redirect(url_for('routes.login'))

    user = Usuario.query.get(login_session['user_id'])
    if user.rol != RolUsuario.DIRECTOR:
        flash("No autorizado", "error")
        return redirect(url_for('routes.chat_index'))

    institucion = Institucion.query.get_or_404(institution_id)
    if institucion.director_id != user.id:
        flash("No autorizado", "error")
        return redirect(url_for('routes.director_panel', institution_id=institution_id))

    # Obtener todos los cursos de la institución
    cursos = Curso.query.filter_by(institucion_id=institution_id).all()
    curso_ids = [c.id for c in cursos] if cursos else []
    
    # Obtener profesores que enseñan en esta institución (TODOS, activos e inactivos)
    profesores = []
    if curso_ids:
        profesores = db.session.query(Usuario).join(
            profesor_curso_materia, Usuario.id == profesor_curso_materia.c.profesor_id
        ).join(
            Curso, profesor_curso_materia.c.curso_id == Curso.id
        ).filter(
            Curso.institucion_id == institution_id,
            Usuario.rol == RolUsuario.PROFESOR
            # Removido el filtro de activo == True
        ).distinct().all()
    
    # Obtener alumnos de la institución (TODOS, activos e inactivos)
    alumnos = []
    if curso_ids:
        alumnos = Usuario.query.filter(
            Usuario.curso_id.in_(curso_ids),
            Usuario.rol == RolUsuario.ALUMNO
            # Removido el filtro de activo == True
        ).all()
    
    # Obtener tutores (TODOS, activos e inactivos)
    tutores = []
    tutor_ids = [c.tutor_id for c in cursos if c.tutor_id]
    if tutor_ids:
        tutores = Usuario.query.filter(
            Usuario.id.in_(tutor_ids),
            Usuario.rol == RolUsuario.TUTOR
            # Removido el filtro de activo == True
        ).all()
    
    # Obtener padres/madres (TODOS, activos e inactivos)
    padres_ids = set()
    for alumno in alumnos:
        if alumno.padre_id:
            padres_ids.add(alumno.padre_id)
        if alumno.madre_id:
            padres_ids.add(alumno.madre_id)
    
    padres = Usuario.query.filter(
        Usuario.id.in_(padres_ids)
        # Removido el filtro de activo == True
    ).all() if padres_ids else []

    # Obtener lista de patologías disponibles para el formulario
    patologias_disponibles = [
        {'value': p.value, 'label': p.value.replace('_', ' ').title()} 
        for p in PatologiaAlumno
    ]

    return render_template('director_users.html', 
                         institucion=institucion,
                         profesores=profesores,
                         alumnos=alumnos,
                         tutores=tutores,
                         padres=padres,
                         cursos=cursos,
                         patologias_disponibles=patologias_disponibles)


@routes.route('/institution/<int:institution_id>/director/users/export/<format>')
def director_export_users(institution_id, format):
    """Exportar datos de usuarios en diferentes formatos"""
    if 'user_id' not in login_session:
        return redirect(url_for('routes.login'))

    user = Usuario.query.get(login_session['user_id'])
    if user.rol != RolUsuario.DIRECTOR:
        flash("No autorizado", "error")
        return redirect(url_for('routes.chat_index'))

    institucion = Institucion.query.get_or_404(institution_id)
    if institucion.director_id != user.id:
        flash("No autorizado", "error")
        return redirect(url_for('routes.director_panel', institution_id=institution_id))

    # Validar formato
    valid_formats = ['excel', 'csv', 'pdf']
    if format.lower() not in valid_formats:
        flash("Formato no válido", "error")
        return redirect(url_for('routes.director_users', institution_id=institution_id))

    try:
        # Obtener todos los usuarios de la institución
        cursos = Curso.query.filter_by(institucion_id=institution_id).all()
        curso_ids = [c.id for c in cursos] if cursos else []
        
        # Recopilar todos los usuarios
        todos_usuarios = []
        
        # Profesores
        if curso_ids:
            profesores = db.session.query(Usuario).join(
                profesor_curso_materia, Usuario.id == profesor_curso_materia.c.profesor_id
            ).join(
                Curso, profesor_curso_materia.c.curso_id == Curso.id
            ).filter(
                Curso.institucion_id == institution_id,
                Usuario.rol == RolUsuario.PROFESOR
            ).distinct().all()
            todos_usuarios.extend(profesores)
        
        # Alumnos
        if curso_ids:
            alumnos = Usuario.query.filter(
                Usuario.curso_id.in_(curso_ids),
                Usuario.rol == RolUsuario.ALUMNO
            ).all()
            todos_usuarios.extend(alumnos)
        
        # Tutores
        tutor_ids = [c.tutor_id for c in cursos if c.tutor_id]
        if tutor_ids:
            tutores = Usuario.query.filter(
                Usuario.id.in_(tutor_ids),
                Usuario.rol == RolUsuario.TUTOR
            ).all()
            todos_usuarios.extend(tutores)
        
        # Padres/Madres
        padres_ids = set()
        for alumno in [u for u in todos_usuarios if u.rol == RolUsuario.ALUMNO]:
            if alumno.padre_id:
                padres_ids.add(alumno.padre_id)
            if alumno.madre_id:
                padres_ids.add(alumno.madre_id)
        
        if padres_ids:
            padres = Usuario.query.filter(Usuario.id.in_(padres_ids)).all()
            todos_usuarios.extend(padres)

        # Preparar datos para exportación
        datos_exportacion = []
        for usuario in todos_usuarios:
            curso_nombre = ""
            if usuario.rol == RolUsuario.ALUMNO and usuario.curso:
                curso_nombre = usuario.curso.nombre
            elif usuario.rol == RolUsuario.TUTOR:
                curso_tutor = Curso.query.filter_by(tutor_id=usuario.id, institucion_id=institution_id).first()
                if curso_tutor:
                    curso_nombre = f"Tutor de {curso_tutor.nombre}"
            elif usuario.rol == RolUsuario.PROFESOR:
                # Obtener cursos que enseña en esta institución
                cursos_profesor = db.session.query(Curso.nombre).join(
                    profesor_curso_materia, Curso.id == profesor_curso_materia.c.curso_id
                ).filter(
                    profesor_curso_materia.c.profesor_id == usuario.id,
                    Curso.institucion_id == institution_id
                ).distinct().all()
                if cursos_profesor:
                    curso_nombre = ", ".join([c[0] for c in cursos_profesor])

            # Obtener patologías si es alumno
            patologias_str = ""
            if usuario.rol == RolUsuario.ALUMNO:
                try:
                    patologias = usuario.get_patologias()
                    if patologias:
                        patologias_list = []
                        for p in patologias:
                            if hasattr(p, 'value'):
                                patologias_list.append(p.value.replace('_', ' ').title())
                            else:
                                patologias_list.append(str(p))
                        patologias_str = ", ".join(patologias_list)
                except:
                    patologias_str = ""

            datos_exportacion.append({
                'ID': usuario.id,
                'Nombre': usuario.nombre,
                'Apellido': usuario.apellido,
                'Email': usuario.email,
                'Rol': usuario.rol.value.title(),
                'Fecha Nacimiento': usuario.fecha_nacimiento.strftime('%d/%m/%Y') if usuario.fecha_nacimiento else '',
                'Curso': curso_nombre,
                'Patologías': patologias_str,
                'Estado': 'Activo' if usuario.activo else 'Inactivo',
                'Fecha Registro': usuario.fecha_creacion.strftime('%d/%m/%Y') if usuario.fecha_creacion else ''
            })

        # Generar archivo según el formato
        if format.lower() == 'excel':
            return export_to_excel(datos_exportacion, f"usuarios_{institucion.nombre}")
        elif format.lower() == 'csv':
            return export_to_csv(datos_exportacion, f"usuarios_{institucion.nombre}")
        elif format.lower() == 'pdf':
            return export_to_pdf(datos_exportacion, f"Usuarios - {institucion.nombre}")

    except Exception as e:
        logger.error(f"Error exportando usuarios: {e}")
        flash("Error al generar el archivo de exportación", "error")
        return redirect(url_for('routes.director_users', institution_id=institution_id))


# Funciones auxiliares para exportación
def export_to_excel(data, filename):
    """Exportar datos a Excel"""
    import io
    import pandas as pd
    from flask import send_file
    
    # Crear DataFrame
    df = pd.DataFrame(data)
    
    # Crear archivo en memoria
    output = io.BytesIO()
    
    # Escribir a Excel
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Usuarios')
        
        # Obtener el workbook y worksheet para formatear
        workbook = writer.book
        worksheet = writer.sheets['Usuarios']
        
        # Ajustar ancho de columnas
        for column in worksheet.columns:
            max_length = 0
            column_letter = column[0].column_letter
            
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            
            adjusted_width = min(max_length + 2, 50)
            worksheet.column_dimensions[column_letter].width = adjusted_width
    
    output.seek(0)
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f'{filename}.xlsx'
    )


def export_to_csv(data, filename):
    """Exportar datos a CSV"""
    import io
    import csv
    from flask import Response
    
    output = io.StringIO()
    
    if data:
        fieldnames = data[0].keys()
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        
        writer.writeheader()
        for row in data:
            writer.writerow(row)
    
    response = Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename={filename}.csv'
        }
    )
    
    return response


def export_to_pdf(data, title):
    """Exportar datos a PDF"""    
    # Crear archivo en memoria
    buffer = io.BytesIO()
    
    # Configurar documento
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    elements = []
    
    # Estilos
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=18,
        textColor=colors.HexColor('#667eea'),
        spaceAfter=30,
        alignment=1  # Centrado
    )
    
    # Título
    title_para = Paragraph(title, title_style)
    elements.append(title_para)
    elements.append(Spacer(1, 12))
    
    # Preparar datos para la tabla
    if data:
        # Headers
        headers = ['Nombre', 'Apellido', 'Email', 'Rol', 'Fecha Nac.', 'Curso', 'Estado']
        table_data = [headers]
        
        # Datos
        for row in data:
            table_data.append([
                row.get('Nombre', ''),
                row.get('Apellido', ''),
                row.get('Email', ''),
                row.get('Rol', ''),
                row.get('Fecha Nacimiento', ''),
                row.get('Curso', '')[:30] + '...' if len(row.get('Curso', '')) > 30 else row.get('Curso', ''),
                row.get('Estado', '')
            ])
        
        # Crear tabla
        table = Table(table_data)
        
        # Estilo de tabla
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(table)
    
    # Construir PDF
    doc.build(elements)
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'{title.replace(" ", "_")}.pdf'
    )


@routes.route('/institution/<int:institution_id>/director/users/invite', methods=['POST'])
def director_invite_user(institution_id):
    """Crear invitación para nuevo usuario con datos completos"""
    if 'user_id' not in login_session:
        return jsonify({'success': False, 'error': 'No autorizado'}), 401

    user = Usuario.query.get(login_session['user_id'])
    if user.rol != RolUsuario.DIRECTOR:
        return jsonify({'success': False, 'error': 'No autorizado'}), 403

    institucion = Institucion.query.get_or_404(institution_id)
    if institucion.director_id != user.id:
        return jsonify({'success': False, 'error': 'No autorizado para esta institución'}), 403

    try:
        data = request.get_json()
        
        # Validar datos básicos requeridos
        required_fields = ['email', 'nombre', 'apellido', 'rol']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'Campo {field} es requerido'}), 400

        email = data['email'].strip().lower()
        nombre = data['nombre'].strip()
        apellido = data['apellido'].strip()
        rol_str = data['rol'].strip().upper()

        # Verificar email único
        if Usuario.query.filter_by(email=email).first():
            return jsonify({'success': False, 'error': 'Este email ya está registrado'}), 400
        
        # Verificar si ya hay una invitación pendiente
        existing_invite = InviteToken.query.filter_by(email=email).first()
        if existing_invite and existing_invite.is_valid():
            return jsonify({'success': False, 'error': 'Ya existe una invitación pendiente para este email'}), 400

        # Convertir y validar rol
        try:
            rol = RolUsuario(rol_str.lower())
        except ValueError:
            return jsonify({'success': False, 'error': 'Rol inválido'}), 400

        # Validaciones específicas por rol
        curso_id = None
        fecha_nacimiento = None
        patologias = []

        # Para ALUMNO: curso y fecha nacimiento requeridos
        if rol == RolUsuario.ALUMNO:
            if not data.get('curso_id'):
                return jsonify({'success': False, 'error': 'Curso es requerido para alumnos'}), 400
            if not data.get('fecha_nacimiento'):
                return jsonify({'success': False, 'error': 'Fecha de nacimiento es requerida para alumnos'}), 400
            
            curso_id = int(data['curso_id'])
            # Verificar que el curso pertenece a esta institución
            curso = Curso.query.get(curso_id)
            if not curso or curso.institucion_id != institution_id:
                return jsonify({'success': False, 'error': 'Curso inválido'}), 400
            
            try:
                fecha_nacimiento = datetime.strptime(data['fecha_nacimiento'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'success': False, 'error': 'Formato de fecha inválido'}), 400
            
            # Procesar patologías si se proporcionan
            if data.get('patologias'):
                patologias = data['patologias']
                # Validar que las patologías existen
                patologias_validas = [p.value for p in PatologiaAlumno]
                for patologia in patologias:
                    if patologia not in patologias_validas:
                        return jsonify({'success': False, 'error': f'Patología "{patologia}" no es válida'}), 400

        # Para TUTOR: puede tener curso asignado
        elif rol == RolUsuario.TUTOR:
            if data.get('curso_id'):
                curso_id = int(data['curso_id'])
                curso = Curso.query.get(curso_id)
                if not curso or curso.institucion_id != institution_id:
                    return jsonify({'success': False, 'error': 'Curso inválido'}), 400
                # Verificar que el curso no tiene tutor
                if curso.tutor_id:
                    return jsonify({'success': False, 'error': 'Este curso ya tiene un tutor asignado'}), 400

        # Para otros roles, fecha de nacimiento opcional pero si se proporciona debe ser válida
        elif data.get('fecha_nacimiento'):
            try:
                fecha_nacimiento = datetime.strptime(data['fecha_nacimiento'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'success': False, 'error': 'Formato de fecha inválido'}), 400

        # Eliminar invitación anterior si existe
        if existing_invite:
            db.session.delete(existing_invite)

        # Crear nueva invitación con datos completos
        token = secrets.token_urlsafe(32)
        expires = datetime.utcnow() + timedelta(days=7)

        # Crear diccionario con datos adicionales
        datos_adicionales = {
            'curso_id': curso_id,
            'fecha_nacimiento': fecha_nacimiento.isoformat() if fecha_nacimiento else None,
            'patologias': patologias,
            'institucion_id': institution_id
        }

        invitation = InviteToken(
            email=email,
            token=token,
            rol=rol,
            nombre=nombre,
            apellido=apellido,
            fecha_expiracion=expires
        )
        
        # Usar el nuevo método para guardar datos adicionales
        invitation.set_datos_adicionales(datos_adicionales)
        
        db.session.add(invitation)
        db.session.commit()

        # Generar mensaje personalizado según el rol
        rol_messages = {
            RolUsuario.PROFESOR: "como profesor",
            RolUsuario.TUTOR: "como tutor",
            RolUsuario.ALUMNO: f"como alumno del curso {curso.nombre}" if curso_id else "como alumno",
            RolUsuario.PADRE: "como padre",
            RolUsuario.MADRE: "como madre"
        }

        # Enviar email de invitación
        invite_url = url_for('routes.accept_invitation', token=token, _external=True)
        
        # Aquí deberías llamar a tu función de envío de email
        try:
            send_invitation_email(
                to_email=email,
                first_name=nombre,
                institution_name=institucion.nombre,
                role=rol_messages.get(rol, rol.value),
                invite_url=invite_url,
                expiration="7 días"
            )
            email_sent = True
        except Exception as e:
            logger.error(f"Error enviando email de invitación: {e}")
            email_sent = False

        response_message = f'Invitación creada para {nombre} {apellido} ({email}) {rol_messages.get(rol, rol.value)}'
        if not email_sent:
            response_message += '. Advertencia: El email no pudo ser enviado.'

        return jsonify({
            'success': True,
            'message': response_message,
            'invitation_id': invitation.id,
            'invite_url': invite_url if not email_sent else None  # Solo incluir URL si el email falló
        })

    except ValueError as ve:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(ve)}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating invitation: {e}")
        return jsonify({'success': False, 'error': 'Error interno del servidor'}), 500


@routes.route('/institution/<int:institution_id>/director/users/<int:user_id>/toggle-status', methods=['POST'])
def director_toggle_user_status(institution_id, user_id):
    """Activar/desactivar usuario"""
    if 'user_id' not in login_session:
        return jsonify({'success': False, 'error': 'No autorizado'}), 401

    director = Usuario.query.get(login_session['user_id'])
    if director.rol != RolUsuario.DIRECTOR:
        return jsonify({'success': False, 'error': 'No autorizado'}), 403

    institucion = Institucion.query.get_or_404(institution_id)
    if institucion.director_id != director.id:
        return jsonify({'success': False, 'error': 'No autorizado'}), 403

    try:
        usuario = Usuario.query.get_or_404(user_id)
        
        # Verificar que el usuario pertenece a la institución
        user_belongs = False
        if usuario.rol == RolUsuario.ALUMNO and usuario.curso:
            user_belongs = usuario.curso.institucion_id == institution_id
        elif usuario.rol == RolUsuario.TUTOR:
            user_belongs = any(c.tutor_id == usuario.id for c in institucion.cursos)
        elif usuario.rol == RolUsuario.PROFESOR:
            # Verificar a través de las materias que enseña
            user_belongs = any(
                m.curso.institucion_id == institution_id 
                for m in usuario.cursos_materias
            )
        
        if not user_belongs:
            return jsonify({'success': False, 'error': 'Usuario no pertenece a esta institución'}), 403
        
        # Cambiar estado
        usuario.activo = not usuario.activo
        db.session.commit()
        
        action = "activado" if usuario.activo else "desactivado"
        return jsonify({
            'success': True,
            'message': f'Usuario {action} exitosamente',
            'new_status': usuario.activo
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error toggling user status: {e}")
        return jsonify({'success': False, 'error': 'Error interno del servidor'}), 500


@routes.route('/institution/<int:institution_id>/director/users/<int:user_id>/edit', methods=['GET', 'POST'])
def director_edit_user(institution_id, user_id):
    """Editar datos de usuario - GET devuelve datos JSON, POST actualiza"""
    if 'user_id' not in login_session:
        if request.method == 'POST':
            return jsonify({'success': False, 'error': 'No autorizado'}), 401
        return redirect(url_for('routes.login'))

    director = Usuario.query.get(login_session['user_id'])
    if director.rol != RolUsuario.DIRECTOR:
        if request.method == 'POST':
            return jsonify({'success': False, 'error': 'No autorizado'}), 403
        flash("No autorizado", "error")
        return redirect(url_for('routes.chat_index'))

    institucion = Institucion.query.get_or_404(institution_id)
    if institucion.director_id != director.id:
        if request.method == 'POST':
            return jsonify({'success': False, 'error': 'No autorizado para esta institución'}), 403
        flash("No autorizado", "error")
        return redirect(url_for('routes.director_panel', institution_id=institution_id))

    usuario = Usuario.query.get_or_404(user_id)

    # Verificar que el usuario pertenece a la institución
    user_belongs = False
    try:
        if usuario.rol == RolUsuario.ALUMNO and usuario.curso:
            user_belongs = usuario.curso.institucion_id == institution_id
        elif usuario.rol == RolUsuario.TUTOR:
            # Verificar si es tutor de algún curso de la institución
            cursos_tutor = Curso.query.filter_by(
                tutor_id=usuario.id,
                institucion_id=institution_id
            ).first()
            user_belongs = cursos_tutor is not None
        elif usuario.rol == RolUsuario.PROFESOR:
            # Verificar a través de las materias que enseña
            user_belongs = any(
                m.curso.institucion_id == institution_id 
                for m in usuario.cursos_materias
            )
        elif usuario.rol in [RolUsuario.PADRE, RolUsuario.MADRE]:
            # Verificar a través de los hijos
            hijos = usuario.get_hijos()
            for hijo in hijos:
                if hijo.curso and hijo.curso.institucion_id == institution_id:
                    user_belongs = True
                    break
    except Exception as e:
        logger.error(f"Error verificando pertenencia del usuario: {e}")
        user_belongs = False
    
    if not user_belongs:
        if request.method == 'POST':
            return jsonify({'success': False, 'error': 'Usuario no pertenece a esta institución'}), 403
        flash("Usuario no pertenece a esta institución", "error")
        return redirect(url_for('routes.director_users', institution_id=institution_id))

    # ========== GET REQUEST - Devolver datos del usuario ==========
    if request.method == 'GET':
        try:
            # Obtener patologías actuales si es alumno
            patologias_actuales = []
            if usuario.rol == RolUsuario.ALUMNO:
                try:
                    patologias_obj = usuario.get_patologias()
                    patologias_actuales = []
                    for p in patologias_obj:
                        if hasattr(p, 'value'):
                            patologias_actuales.append(p.value)
                        else:
                            patologias_actuales.append(str(p))
                except Exception as e:
                    logger.error(f"Error obteniendo patologías: {e}")
                    patologias_actuales = []

            # Preparar datos del usuario
            user_data = {
                'id': usuario.id,
                'nombre': usuario.nombre,
                'apellido': usuario.apellido,
                'email': usuario.email,
                'rol': usuario.rol.value,
                'rol_display': usuario.rol.value.title(),
                'activo': usuario.activo,
                'fecha_nacimiento': usuario.fecha_nacimiento.strftime('%Y-%m-%d') if usuario.fecha_nacimiento else '',
                'curso_id': usuario.curso_id if hasattr(usuario, 'curso_id') else None,
                'patologias': patologias_actuales,
                'fecha_creacion': usuario.fecha_creacion.strftime('%d/%m/%Y %H:%M') if usuario.fecha_creacion else 'N/A',
                'fecha_actualizacion': usuario.fecha_actualizacion.strftime('%d/%m/%Y %H:%M') if usuario.fecha_actualizacion else 'N/A'
            }

            # Información adicional según el rol
            if usuario.rol == RolUsuario.ALUMNO and usuario.curso:
                user_data['curso_nombre'] = usuario.curso.nombre
            elif usuario.rol == RolUsuario.TUTOR and usuario.curso_tutor:
                user_data['curso_tutor_nombre'] = usuario.curso_tutor.nombre

            return jsonify({
                'success': True,
                'user': user_data
            })

        except Exception as e:
            logger.error(f"Error obteniendo datos del usuario: {e}")
            return jsonify({'success': False, 'error': 'Error interno del servidor'}), 500

    # ========== POST REQUEST - Actualizar usuario ==========
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({'success': False, 'error': 'No se recibieron datos'}), 400

            # Validar datos básicos
            changes_made = []

            # Actualizar nombre
            if 'nombre' in data and data['nombre'].strip():
                new_nombre = data['nombre'].strip()
                if new_nombre != usuario.nombre:
                    usuario.nombre = new_nombre
                    changes_made.append('nombre')

            # Actualizar apellido
            if 'apellido' in data and data['apellido'].strip():
                new_apellido = data['apellido'].strip()
                if new_apellido != usuario.apellido:
                    usuario.apellido = new_apellido
                    changes_made.append('apellido')

            # Actualizar email
            if 'email' in data and data['email'].strip():
                new_email = data['email'].strip().lower()
                if new_email != usuario.email:
                    # Verificar que el email no esté en uso por otro usuario
                    existing = Usuario.query.filter(
                        Usuario.email == new_email,
                        Usuario.id != user_id
                    ).first()
                    if existing:
                        return jsonify({'success': False, 'error': 'Este email ya está en uso por otro usuario'}), 400
                    
                    usuario.email = new_email
                    changes_made.append('email')

            # Actualizar fecha de nacimiento (todos los roles)
            if 'fecha_nacimiento' in data and data['fecha_nacimiento']:
                try:
                    new_fecha = datetime.strptime(data['fecha_nacimiento'], '%Y-%m-%d').date()
                    if new_fecha != usuario.fecha_nacimiento:
                        usuario.fecha_nacimiento = new_fecha
                        changes_made.append('fecha de nacimiento')
                except ValueError:
                    return jsonify({'success': False, 'error': 'Formato de fecha inválido'}), 400

            # Actualizaciones específicas para ALUMNO
            if usuario.rol == RolUsuario.ALUMNO:
                # Actualizar curso
                if 'curso_id' in data:
                    new_curso_id = data['curso_id'] if data['curso_id'] else None
                    if new_curso_id != usuario.curso_id:
                        if new_curso_id:
                            # Verificar que el curso existe y pertenece a esta institución
                            curso = Curso.query.get(new_curso_id)
                            if not curso or curso.institucion_id != institution_id:
                                return jsonify({'success': False, 'error': 'Curso inválido'}), 400
                        
                        usuario.curso_id = new_curso_id
                        changes_made.append('curso')

                # Actualizar patologías
                if 'patologias' in data:
                    new_patologias = data['patologias'] if data['patologias'] else []
                    
                    # Obtener patologías actuales
                    try:
                        current_patologias = usuario.get_patologias()
                        current_patologias_values = []
                        for p in current_patologias:
                            if hasattr(p, 'value'):
                                current_patologias_values.append(p.value)
                            else:
                                current_patologias_values.append(str(p))
                    except Exception as e:
                        logger.error(f"Error obteniendo patologías actuales: {e}")
                        current_patologias_values = []

                    # Comparar si hay cambios
                    if set(new_patologias) != set(current_patologias_values):
                        # Validar que las nuevas patologías son válidas
                        patologias_validas = [p.value for p in PatologiaAlumno]
                        for patologia in new_patologias:
                            if patologia not in patologias_validas:
                                return jsonify({'success': False, 'error': f'Patología "{patologia}" no es válida'}), 400

                        # Eliminar patologías actuales
                        try:
                            for patologia in current_patologias:
                                usuario.remover_patologia(patologia)
                        except Exception as e:
                            logger.error(f"Error removiendo patologías: {e}")

                        # Agregar nuevas patologías
                        try:
                            for patologia_value in new_patologias:
                                usuario.agregar_patologia(patologia_value)
                        except Exception as e:
                            logger.error(f"Error agregando patologías: {e}")
                            return jsonify({'success': False, 'error': 'Error actualizando patologías'}), 500

                        changes_made.append('patologías')

            # Actualizar fecha de actualización
            usuario.fecha_actualizacion = datetime.utcnow()
            
            # Guardar cambios
            db.session.commit()
            
            # Preparar mensaje de respuesta
            if changes_made:
                cambios_texto = ', '.join(changes_made)
                message = f'Usuario actualizado exitosamente. Cambios realizados: {cambios_texto}'
            else:
                message = 'No se detectaron cambios en los datos del usuario'
            
            logger.info(f"Usuario {usuario.email} actualizado por director {director.email}. Cambios: {changes_made}")
            
            return jsonify({
                'success': True,
                'message': message,
                'changes_made': changes_made
            })

        except ValueError as ve:
            db.session.rollback()
            logger.error(f"Error de validación actualizando usuario: {ve}")
            return jsonify({'success': False, 'error': str(ve)}), 400
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error actualizando usuario: {e}")
            return jsonify({'success': False, 'error': 'Error interno del servidor'}), 500

    # Nunca debería llegar aquí
    return jsonify({'success': False, 'error': 'Método no permitido'}), 405

@routes.route('/institution/<int:institution_id>/director/courses')
def director_courses(institution_id):
    """Gestión de cursos y materias"""
    if 'user_id' not in login_session:
        return redirect(url_for('routes.login'))

    user = Usuario.query.get(login_session['user_id'])
    if user.rol != RolUsuario.DIRECTOR:
        flash("No autorizado", "error")
        return redirect(url_for('routes.chat_index'))

    institucion = Institucion.query.get_or_404(institution_id)
    if institucion.director_id != user.id:
        flash("No autorizado", "error")
        return redirect(url_for('routes.director_panel', institution_id=institution_id))

    try:
        # Obtener cursos con información de profesores por materia
        cursos = Curso.query.filter_by(institucion_id=institution_id).all()
        
        # Para cada curso, obtener las materias y sus profesores asignados
        for curso in cursos:
            # Asegurar que curso.materias esté inicializado
            if not hasattr(curso, 'materias'):
                curso.materias = []
                
            for materia in curso.materias:
                try:
                    # Obtener profesor asignado a esta materia específica
                    profesor = db.session.query(Usuario).join(
                        profesor_curso_materia, Usuario.id == profesor_curso_materia.c.profesor_id
                    ).filter(
                        profesor_curso_materia.c.materia_id == materia.id,
                        profesor_curso_materia.c.curso_id == curso.id,
                        Usuario.activo == True
                    ).first()
                    
                    # Agregar profesor a la materia como atributo temporal
                    materia.profesor_asignado = profesor
                    
                except Exception as e:
                    logger.error(f"Error obteniendo profesor para materia {materia.id}: {e}")
                    materia.profesor_asignado = None
        
        # Obtener profesores disponibles (todos los profesores activos)
        profesores = Usuario.query.filter_by(rol=RolUsuario.PROFESOR, activo=True).all()
        tutores = Usuario.query.filter_by(rol=RolUsuario.TUTOR, activo=True).all()

        return render_template('director_courses.html', 
                             institucion=institucion,
                             cursos=cursos,
                             profesores=profesores,
                             tutores=tutores)
                             
    except Exception as e:
        logger.error(f"Error in director_courses: {e}")
        flash("Error cargando la página de cursos", "error")
        return redirect(url_for('routes.director_panel', institution_id=institution_id))

@routes.route('/institution/<int:institution_id>/director/courses/create', methods=['POST'])
def director_create_course(institution_id):
    """Crear nuevo curso"""
    if 'user_id' not in login_session:
        return jsonify({'error': 'no autorizado'}), 401

    user = Usuario.query.get(login_session['user_id'])
    if user.rol != RolUsuario.DIRECTOR:
        return jsonify({'error': 'no autorizado'}), 403

    institucion = Institucion.query.get_or_404(institution_id)
    if institucion.director_id != user.id:
        return jsonify({'error': 'no autorizado'}), 403

    try:
        data = request.get_json()
        
        nuevo_curso = Curso(
            nombre=data['nombre'],
            nivel=data.get('nivel', ''),
            institucion_id=institution_id,
            tutor_id=data.get('tutor_id') if data.get('tutor_id') else None
        )
        
        db.session.add(nuevo_curso)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Curso creado exitosamente',
            'course_id': nuevo_curso.id
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating course: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@routes.route('/institution/<int:institution_id>/director/courses/<int:course_id>/edit', methods=['POST'])
def director_edit_course(institution_id, course_id):
    """Editar curso existente"""
    if 'user_id' not in login_session:
        return jsonify({'success': False, 'error': 'No autorizado'}), 401

    user = Usuario.query.get(login_session['user_id'])
    if user.rol != RolUsuario.DIRECTOR:
        return jsonify({'success': False, 'error': 'No autorizado'}), 403

    institucion = Institucion.query.get_or_404(institution_id)
    if institucion.director_id != user.id:
        return jsonify({'success': False, 'error': 'No autorizado para esta institución'}), 403

    curso = Curso.query.get_or_404(course_id)
    if curso.institucion_id != institution_id:
        return jsonify({'success': False, 'error': 'Curso no pertenece a esta institución'}), 403

    try:
        data = request.get_json()
        
        # Actualizar datos del curso
        curso.nombre = data.get('nombre', curso.nombre)
        curso.nivel = data.get('nivel', curso.nivel)
        
        # Actualizar tutor si se proporciona
        new_tutor_id = data.get('tutor_id')
        if new_tutor_id == '':  # String vacío = sin tutor
            curso.tutor_id = None
        elif new_tutor_id:
            # Verificar que el tutor existe
            tutor = Usuario.query.filter_by(id=new_tutor_id, rol=RolUsuario.TUTOR).first()
            if not tutor:
                return jsonify({'success': False, 'error': 'Tutor inválido'}), 400
            curso.tutor_id = new_tutor_id
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Curso actualizado exitosamente'
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating course: {e}")
        return jsonify({'success': False, 'error': 'Error interno del servidor'}), 500


@routes.route('/institution/<int:institution_id>/director/courses/<int:course_id>/delete', methods=['DELETE'])
def director_delete_course(institution_id, course_id):
    """Eliminar curso"""
    if 'user_id' not in login_session:
        return jsonify({'success': False, 'error': 'No autorizado'}), 401

    user = Usuario.query.get(login_session['user_id'])
    if user.rol != RolUsuario.DIRECTOR:
        return jsonify({'success': False, 'error': 'No autorizado'}), 403

    institucion = Institucion.query.get_or_404(institution_id)
    if institucion.director_id != user.id:
        return jsonify({'success': False, 'error': 'No autorizado para esta institución'}), 403

    curso = Curso.query.get_or_404(course_id)
    if curso.institucion_id != institution_id:
        return jsonify({'success': False, 'error': 'Curso no pertenece a esta institución'}), 403

    try:
        # Verificar si hay alumnos asignados al curso
        alumnos_count = Usuario.query.filter_by(curso_id=course_id, rol=RolUsuario.ALUMNO).count()
        if alumnos_count > 0:
            return jsonify({
                'success': False, 
                'error': f'No se puede eliminar el curso. Hay {alumnos_count} alumno(s) asignado(s)'
            }), 400

        # Eliminar materias del curso (esto eliminará también las relaciones con profesores)
        for materia in curso.materias:
            db.session.delete(materia)
        
        # Eliminar el curso
        db.session.delete(curso)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Curso eliminado exitosamente'
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting course: {e}")
        return jsonify({'success': False, 'error': 'Error interno del servidor'}), 500


@routes.route('/institution/<int:institution_id>/director/subjects/<int:subject_id>/edit', methods=['POST'])
def director_edit_subject(institution_id, subject_id):
    """Editar materia existente"""
    if 'user_id' not in login_session:
        return jsonify({'success': False, 'error': 'No autorizado'}), 401

    user = Usuario.query.get(login_session['user_id'])
    if user.rol != RolUsuario.DIRECTOR:
        return jsonify({'success': False, 'error': 'No autorizado'}), 403

    institucion = Institucion.query.get_or_404(institution_id)
    if institucion.director_id != user.id:
        return jsonify({'success': False, 'error': 'No autorizado para esta institución'}), 403

    materia = Materia.query.get_or_404(subject_id)
    if materia.curso.institucion_id != institution_id:
        return jsonify({'success': False, 'error': 'Materia no pertenece a esta institución'}), 403

    try:
        data = request.get_json()
        
        # Actualizar datos de la materia
        materia.nombre = data.get('nombre', materia.nombre)
        materia.descripcion = data.get('descripcion', materia.descripcion)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Materia actualizada exitosamente'
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating subject: {e}")
        return jsonify({'success': False, 'error': 'Error interno del servidor'}), 500


@routes.route('/institution/<int:institution_id>/director/subjects/<int:subject_id>/delete', methods=['DELETE'])
def director_delete_subject(institution_id, subject_id):
    """Eliminar materia"""
    if 'user_id' not in login_session:
        return jsonify({'success': False, 'error': 'No autorizado'}), 401

    user = Usuario.query.get(login_session['user_id'])
    if user.rol != RolUsuario.DIRECTOR:
        return jsonify({'success': False, 'error': 'No autorizado'}), 403

    institucion = Institucion.query.get_or_404(institution_id)
    if institucion.director_id != user.id:
        return jsonify({'success': False, 'error': 'No autorizado para esta institución'}), 403

    materia = Materia.query.get_or_404(subject_id)
    if materia.curso.institucion_id != institution_id:
        return jsonify({'success': False, 'error': 'Materia no pertenece a esta institución'}), 403

    try:
        # Verificar si hay archivos subidos para esta materia
        archivos_count = ArchivoMateria.query.filter_by(materia_id=subject_id).count()
        if archivos_count > 0:
            return jsonify({
                'success': False, 
                'error': f'No se puede eliminar la materia. Hay {archivos_count} archivo(s) asociado(s)'
            }), 400
        
        # Eliminar la materia (esto eliminará automáticamente las relaciones con profesores)
        db.session.delete(materia)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Materia eliminada exitosamente'
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting subject: {e}")
        return jsonify({'success': False, 'error': 'Error interno del servidor'}), 500

@routes.route('/institution/<int:institution_id>/director/courses/<int:course_id>/subjects', methods=['POST'])
def director_add_subject(institution_id, course_id):
    """Agregar materia a un curso"""
    if 'user_id' not in login_session:
        return jsonify({'error': 'no autorizado'}), 401

    user = Usuario.query.get(login_session['user_id'])
    if user.rol != RolUsuario.DIRECTOR:
        return jsonify({'error': 'no autorizado'}), 403

    institucion = Institucion.query.get_or_404(institution_id)
    if institucion.director_id != user.id:
        return jsonify({'error': 'no autorizado'}), 403

    curso = Curso.query.get_or_404(course_id)
    if curso.institucion_id != institution_id:
        return jsonify({'error': 'Curso no pertenece a esta institución'}), 403

    try:
        data = request.get_json()
        
        nueva_materia = Materia(
            nombre=data['nombre'],
            descripcion=data.get('descripcion', ''),
            curso_id=course_id
        )
        
        db.session.add(nueva_materia)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Materia creada exitosamente',
            'subject_id': nueva_materia.id
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating subject: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@routes.route('/institution/<int:institution_id>/director/analytics')
def director_analytics(institution_id):
    """Panel principal de analíticas"""
    if 'user_id' not in login_session:
        return redirect(url_for('routes.login'))

    user = Usuario.query.get(login_session['user_id'])
    if user.rol != RolUsuario.DIRECTOR:
        flash("No autorizado", "error")
        return redirect(url_for('routes.chat_index'))

    institucion = Institucion.query.get_or_404(institution_id)
    if institucion.director_id != user.id:
        flash("No autorizado", "error")
        return redirect(url_for('routes.director_panel', institution_id=institution_id))

    return render_template('director_analytics.html', institucion=institucion)


@routes.route('/api/institution/<int:institution_id>/director/analytics/comprehension')
def director_analytics_comprehension(institution_id):
    """API para analíticas de comprensión"""
    if 'user_id' not in login_session:
        return jsonify({'error': 'no autorizado'}), 401

    user = Usuario.query.get(login_session['user_id'])
    if user.rol != RolUsuario.DIRECTOR:
        return jsonify({'error': 'no autorizado'}), 403

    institucion = Institucion.query.get_or_404(institution_id)
    if institucion.director_id != user.id:
        return jsonify({'error': 'no autorizado'}), 403

    try:
        # Parámetros de filtro
        curso_id = request.args.get('curso_id', type=int)
        materia_id = request.args.get('materia_id', type=int)
        alumno_id = request.args.get('alumno_id', type=int)
        fecha_inicio = request.args.get('fecha_inicio')
        fecha_fin = request.args.get('fecha_fin')

        # Obtener cursos de la institución
        cursos = Curso.query.filter_by(institucion_id=institution_id).all()
        curso_ids = [c.id for c in cursos]

        # Query base
        query = db.session.query(AnalyticaComprension).join(Usuario).filter(
            Usuario.curso_id.in_(curso_ids)
        )

        # Aplicar filtros
        if curso_id:
            query = query.filter(AnalyticaComprension.curso_id == curso_id)
        if materia_id:
            query = query.filter(AnalyticaComprension.materia_id == materia_id)
        if alumno_id:
            query = query.filter(AnalyticaComprension.alumno_id == alumno_id)
        if fecha_inicio:
            fecha_inicio_dt = datetime.strptime(fecha_inicio, '%Y-%m-%d').date()
            query = query.filter(AnalyticaComprension.periodo_inicio >= fecha_inicio_dt)
        if fecha_fin:
            fecha_fin_dt = datetime.strptime(fecha_fin, '%Y-%m-%d').date()
            query = query.filter(AnalyticaComprension.periodo_fin <= fecha_fin_dt)

        analiticas = query.all()
        
        # Procesar datos
        result = []
        for analytic in analiticas:
            result.append({
                'alumno_id': analytic.alumno_id,
                'alumno_nombre': f"{analytic.alumno.nombre} {analytic.alumno.apellido}",
                'materia_nombre': analytic.materia.nombre if analytic.materia else 'Todas',
                'curso_nombre': analytic.curso.nombre if analytic.curso else 'Todos',
                'promedio_comprension': analytic.promedio_comprension,
                'total_interacciones': analytic.total_interacciones,
                'fecha_calculo': analytic.fecha_calculo.isoformat(),
                'periodo_inicio': analytic.periodo_inicio.isoformat() if analytic.periodo_inicio else None,
                'periodo_fin': analytic.periodo_fin.isoformat() if analytic.periodo_fin else None
            })

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error getting comprehension analytics: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@routes.route('/api/institution/<int:institution_id>/director/analytics/sensitive-content')
def director_analytics_sensitive(institution_id):
    """API para analíticas de contenido sensible"""
    if 'user_id' not in login_session:
        return jsonify({'error': 'no autorizado'}), 401

    user = Usuario.query.get(login_session['user_id'])
    if user.rol != RolUsuario.DIRECTOR:
        return jsonify({'error': 'no autorizado'}), 403

    institucion = Institucion.query.get_or_404(institution_id)
    if institucion.director_id != user.id:
        return jsonify({'error': 'no autorizado'}), 403

    try:
        # Obtener alumnos de la institución
        cursos = Curso.query.filter_by(institucion_id=institution_id).all()
        curso_ids = [c.id for c in cursos]
        alumnos = Usuario.query.filter(
            Usuario.curso_id.in_(curso_ids),
            Usuario.rol == RolUsuario.ALUMNO
        ).all()
        alumno_ids = [a.id for a in alumnos]

        # Parámetros de filtro
        fecha_inicio = request.args.get('fecha_inicio')
        fecha_fin = request.args.get('fecha_fin')
        tipo_contenido = request.args.get('tipo_contenido')
        nivel_riesgo = request.args.get('nivel_riesgo')

        # Query
        query = AlertaContenidoSensible.query.filter(
            AlertaContenidoSensible.alumno_id.in_(alumno_ids)
        )

        if fecha_inicio:
            fecha_inicio_dt = datetime.strptime(fecha_inicio, '%Y-%m-%d')
            query = query.filter(AlertaContenidoSensible.fecha_alerta >= fecha_inicio_dt)
        if fecha_fin:
            fecha_fin_dt = datetime.strptime(fecha_fin, '%Y-%m-%d')
            query = query.filter(AlertaContenidoSensible.fecha_alerta <= fecha_fin_dt)
        if tipo_contenido:
            query = query.filter(AlertaContenidoSensible.tipo_contenido == tipo_contenido)
        if nivel_riesgo:
            query = query.filter(AlertaContenidoSensible.nivel_riesgo == nivel_riesgo)

        alertas = query.order_by(AlertaContenidoSensible.fecha_alerta.desc()).all()

        result = []
        for alerta in alertas:
            result.append({
                'id': alerta.id,
                'alumno_nombre': f"{alerta.alumno.nombre} {alerta.alumno.apellido}",
                'tipo_contenido': alerta.tipo_contenido,
                'contexto': alerta.contexto[:200] + '...' if len(alerta.contexto) > 200 else alerta.contexto,
                'nivel_riesgo': alerta.nivel_riesgo,
                'fecha_alerta': alerta.fecha_alerta.isoformat(),
                'revisada': alerta.revisada
            })

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error getting sensitive content analytics: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@routes.route('/api/institution/<int:institution_id>/director/analytics/learning-questions')
def director_analytics_learning_questions(institution_id):
    """API para analíticas de 'Aprendiendo a preguntar'"""
    if 'user_id' not in login_session:
        return jsonify({'error': 'no autorizado'}), 401

    user = Usuario.query.get(login_session['user_id'])
    if user.rol != RolUsuario.DIRECTOR:
        return jsonify({'error': 'no autorizado'}), 403

    institucion = Institucion.query.get_or_404(institution_id)
    if institucion.director_id != user.id:
        return jsonify({'error': 'no autorizado'}), 403

    try:
        # Obtener alumnos de la institución
        cursos = Curso.query.filter_by(institucion_id=institution_id).all()
        curso_ids = [c.id for c in cursos]
        alumnos = Usuario.query.filter(
            Usuario.curso_id.in_(curso_ids),
            Usuario.rol == RolUsuario.ALUMNO
        ).all()
        alumno_ids = [a.id for a in alumnos]

        # Query sesiones
        sesiones = SesionAprendiendoPreguntar.query.filter(
            SesionAprendiendoPreguntar.alumno_id.in_(alumno_ids)
        ).order_by(SesionAprendiendoPreguntar.fecha_sesion.desc()).all()

        result = []
        for sesion in sesiones:
            result.append({
                'id': sesion.id,
                'alumno_nombre': f"{sesion.alumno.nombre} {sesion.alumno.apellido}",
                'tema': sesion.tema,
                'pregunta_alumno': sesion.pregunta_alumno[:100] + '...' if sesion.pregunta_alumno and len(sesion.pregunta_alumno) > 100 else sesion.pregunta_alumno,
                'exito_sesion': sesion.exito_sesion,
                'fecha_sesion': sesion.fecha_sesion.isoformat()
            })

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error getting learning questions analytics: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@routes.route('/api/institution/<int:institution_id>/director/analytics/file-utility')
def director_analytics_file_utility(institution_id):
    """API para analíticas de utilidad de archivos subidos por profesores"""
    if 'user_id' not in login_session:
        return jsonify({'error': 'no autorizado'}), 401

    user = Usuario.query.get(login_session['user_id'])
    if user.rol != RolUsuario.DIRECTOR:
        return jsonify({'error': 'no autorizado'}), 403

    institucion = Institucion.query.get_or_404(institution_id)
    if institucion.director_id != user.id:
        return jsonify({'error': 'no autorizado'}), 403

    try:
        # Obtener archivos de materias de la institución
        archivos = db.session.query(ArchivoMateria).join(Materia).join(Curso).filter(
            Curso.institucion_id == institution_id
        ).order_by(ArchivoMateria.fecha_subida.desc()).all()

        result = []
        for archivo in archivos:
            profesor = Usuario.query.get(archivo.profesor_id)
            result.append({
                'id': archivo.id,
                'nombre_tema': archivo.nombre_tema,
                'profesor_nombre': f"{profesor.nombre} {profesor.apellido}" if profesor else 'N/A',
                'materia_nombre': archivo.materia.nombre,
                'curso_nombre': archivo.materia.curso.nombre,
                'utilidad_ia_score': archivo.utilidad_ia_score,
                'fecha_subida': archivo.fecha_subida.isoformat(),
                'tareas_generadas': len(archivo.tareas_generadas)
            })

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error getting file utility analytics: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500
