import smtplib
from email.message import EmailMessage
import os
import secrets
from flask import session
from app.models import User
from app import db
def send_invitation_email(to_email, first_name, invite_url, expiration="48 horas"):
    EMAIL_ADDRESS = os.getenv('MAIL_USERNAME')
    EMAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    SMTP_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.getenv('MAIL_PORT', 587))

    # Cargar plantillas
    base_dir = os.path.join(os.path.dirname(__file__), 'templates')
    html_path = os.path.join(base_dir, 'invitation.html')
    txt_path = os.path.join(base_dir, 'invitation.txt')

    with open(html_path, encoding='utf-8') as f:
        html_body = f.read().replace('{{ first_name }}', first_name)\
                            .replace('{{ invite_url }}', invite_url)\
                            .replace('{{ expiration }}', expiration)

    with open(txt_path, encoding='utf-8') as f:
        text_body = f.read().replace('{{ first_name }}', first_name)\
                            .replace('{{ invite_url }}', invite_url)\
                            .replace('{{ expiration }}', expiration)

    msg = EmailMessage()
    msg['Subject'] = 'Invitación a registrarte'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_email

    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype='html')

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
            print(f"[OK] Invitación enviada a {to_email}")
    except Exception as e:
        print(f"[ERROR] No se pudo enviar el email a {to_email}: {e}")
