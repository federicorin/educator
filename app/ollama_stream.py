"""
ollama_stream.py - MODIFICADO PARA GROQ
Módulo para manejo de streaming usando EXCLUSIVAMENTE Groq Cloud
Llama 3.3 70B en todos los casos (local y producción)
"""

import json
import re
import time
import logging
import os
from typing import Generator, Dict, Any, List, Optional
from datetime import datetime

# NUEVA IMPORTACIÓN: Groq
from groq import Groq

# Configuración de logging
logger = logging.getLogger(__name__)

class GroqConfig:
    """Configuración centralizada para Groq Cloud"""
    def __init__(self, api_key: Optional[str] = None, model: str = "llama-3.3-70b-versatile"):
        self.api_key = api_key or os.environ.get('GROQ_API_KEY')
        self.model = model
        if not self.api_key:
            raise ValueError("GROQ_API_KEY requerida. Obtén una gratis en https://console.groq.com/keys")
    
    def __str__(self):
        masked_key = f"{self.api_key[:8]}..." if self.api_key else "None"
        return f"GroqConfig(model={self.model}, api_key={masked_key})"

# Instancia global de configuración
config = GroqConfig()

def set_groq_config(api_key: Optional[str] = None, model: str = "llama-3.3-70b-versatile"):
    """Configura la conexión a Groq Cloud"""
    global config
    config = GroqConfig(api_key=api_key, model=model)
    logger.info(f"Configuración Groq actualizada: {config}")

def limpiar_output(texto: str, preserve_trailing_space: bool = False) -> str:
    """
    Limpia el texto de caracteres ANSI, spinners y formato extra.
    Si preserve_trailing_space es True, NO eliminará los espacios finales,
    pero sí eliminará saltos de línea terminales extras.
    """
    if not texto:
        return ""

    # Remover secuencias de escape ANSI
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    limpio = ansi_escape.sub('', texto)

    # Remover caracteres de spinner
    spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    limpio = ''.join(c for c in limpio if c not in spinner_chars)

    # Normalizar saltos de línea múltiples
    limpio = re.sub(r'\n{3,}', '\n\n', limpio)

    if preserve_trailing_space:
        return re.sub(r'[\r\n]+$', '', limpio)
    else:
        return limpio.strip()

class GroqClient:
    """Cliente unificado para Groq Cloud"""
    
    def __init__(self):
        if not config.api_key:
            raise ValueError("Configuración Groq no inicializada. Usa set_groq_config() primero.")
        self.client = Groq(api_key=config.api_key)
    
    def chat_completion(self, messages: List[Dict[str, str]], temperature: float = 0.8) -> str:
        """Completa un chat sin streaming usando Groq"""
        try:
            completion = self.client.chat.completions.create(
                model=config.model,
                messages=messages,
                temperature=temperature,
                max_completion_tokens=4096,  # Generoso para respuestas educativas
                top_p=0.95,
                stream=False,
                stop=None
            )
            
            response = completion.choices[0].message.content
            return limpiar_output(response) if response else ""
            
        except Exception as e:
            logger.error(f"Error en Groq completion: {e}")
            raise
    
    def stream_completion(self, messages: List[Dict[str, str]], temperature: float = 0.8) -> Generator[str, None, None]:
        """Stream de chat usando Groq Cloud"""
        try:
            completion = self.client.chat.completions.create(
                model=config.model,
                messages=messages,
                temperature=temperature,
                max_completion_tokens=4096,
                top_p=0.95,
                stream=True,
                stop=None
            )
            
            for chunk in completion:
                content = chunk.choices[0].delta.content
                if content:
                    # Limpiar y procesar chunk
                    clean_chunk = limpiar_output(content, preserve_trailing_space=True)
                    if clean_chunk:
                        yield clean_chunk
                        
        except Exception as e:
            logger.error(f"Error en Groq streaming: {e}")
            yield f"Error: No pude procesar tu consulta con Groq. {str(e)}"

def test_groq_connection() -> bool:
    """Prueba la conexión con Groq Cloud"""
    try:
        client = GroqClient()
        test_messages = [{"role": "user", "content": "Hola, responde solo 'OK'"}]
        response = client.chat_completion(test_messages)
        
        if response:
            logger.info("✅ Conexión con Groq Cloud exitosa")
            return True
        else:
            logger.error("❌ Groq respondió vacío")
            return False
            
    except Exception as e:
        logger.error(f"❌ Error probando Groq: {e}")
        return False

def build_system_prompt(user_customize_ai: str = "", kb_context: str = "") -> str:
    """
    Construye el prompt del sistema combinando personalización y contexto
    Optimizado para educación con Llama 3.3 70B
    """
    base_prompt = """Eres un asistente educativo experto powered by Llama 3.3 70B. Tu función es ayudar a estudiantes y educadores proporcionando explicaciones claras, detalladas y pedagógicamente sólidas.

Características de tus respuestas:
- Explica conceptos paso a paso con ejemplos prácticos
- Adapta el nivel de complejidad al contexto del usuario
- Fomenta el pensamiento crítico y la curiosidad
- Proporciona recursos adicionales cuando sea apropiado
- Usa un lenguaje claro y accesible
- Estructura la información de manera lógica y fácil de seguir"""
    
    parts = [base_prompt]
    
    if user_customize_ai.strip():
        parts.append(f"Contexto del usuario: {user_customize_ai.strip()}")
    
    if kb_context.strip():
        parts.append(f"Información relevante de la base de conocimientos: {kb_context.strip()}")
    
    return "\n\n".join(parts)

def prepare_messages(user_customize_ai: str, kb_context: str, prompt: str) -> List[Dict[str, str]]:
    """Prepara los mensajes para la API de Groq"""
    system_content = build_system_prompt(user_customize_ai, kb_context)
    
    messages = [
        {"role": "system", "content": system_content},
        {"role": "user", "content": prompt}
    ]
    
    return messages

def stream_chat_for_user(
    user_customize_ai: str = "",
    kb_context: str = "",
    prompt: str = "",
    model: str = None,  # Ignorado, siempre usa Groq
    timeout: int = None  # Ignorado, Groq maneja internamente
) -> Generator[str, None, None]:
    """
    Genera un stream de chat usando EXCLUSIVAMENTE Groq Cloud
    """
    if not prompt.strip():
        yield "Error: El prompt no puede estar vacío."
        return
    
    # Preparar mensajes
    messages = prepare_messages(user_customize_ai, kb_context, prompt)
    
    logger.info(f"🚀 Iniciando stream con Groq Cloud - Modelo: {config.model}")
    
    try:
        groq_client = GroqClient()
        
        for chunk in groq_client.stream_completion(messages):
            if chunk:
                yield chunk
                
    except Exception as e:
        logger.error(f"Error en streaming Groq: {e}")
        yield f"⚠️ Error: No pude procesar tu consulta. Detalles: {str(e)}"

def chat_once(
    messages: List[Dict[str, str]],
    model: str = None,  # Ignorado, siempre usa Groq
    timeout: int = None  # Ignorado
) -> str:
    """
    Realiza una sola consulta usando EXCLUSIVAMENTE Groq Cloud
    """
    logger.info(f"💬 Consulta única con Groq Cloud - Modelo: {config.model}")
    
    try:
        groq_client = GroqClient()
        response = groq_client.chat_completion(messages)
        
        logger.info(f"✅ Consulta completada: {len(response)} caracteres")
        return response
        
    except Exception as e:
        logger.error(f"Error en consulta Groq: {e}")
        return f"⚠️ Error: No pude procesar tu consulta. Detalles: {str(e)}"

def set_debug_mode(enabled: bool = True):
    """Habilita/deshabilita el modo debug para logging detallado"""
    level = logging.DEBUG if enabled else logging.INFO
    logging.getLogger(__name__).setLevel(level)
    logger.info(f"Modo debug {'habilitado' if enabled else 'deshabilitado'}")

def get_available_models() -> List[str]:
    """Obtiene la lista de modelos disponibles en Groq"""
    return [
        "llama-3.3-70b-versatile",    # 🎯 Recomendado (default)
        "llama-3.1-70b-versatile",
        "llama-3.1-8b-instant",
        "mixtral-8x7b-32768",
        "gemma2-9b-it"
    ]

# Función especial para KnowledgeBase
def ollama_run_for_kb(model: str, prompt: str) -> str:
    """
    Función para reemplazar subprocess en KnowledgeBase
    Ahora usa Groq Cloud en lugar de Ollama local
    """
    try:
        messages = [{"role": "user", "content": prompt}]
        response = chat_once(messages)
        return response
    except Exception as e:
        logger.error(f"Error en ollama_run_for_kb: {e}")
        return f"⚠️ Error al procesar consulta: {e}"

# FUNCIONES DE UTILIDAD Y TESTING

def test_stream_functionality(prompt: str = "Explica el concepto de fotosíntesis de manera didáctica para estudiantes de secundaria"):
    """Función de prueba para verificar que el streaming funciona correctamente"""
    print(f"🧪 Probando streaming Groq con prompt: '{prompt}'")
    print(f"🔧 Modelo configurado: {config.model}")
    print(f"🔑 API Key: {config.api_key[:8] if config.api_key else 'NO CONFIGURADA'}...")
    
    try:
        accumulated = ""
        chunk_count = 0
        start_time = time.time()
        
        for chunk in stream_chat_for_user(prompt=prompt):
            accumulated += chunk
            chunk_count += 1
            print(f"Chunk #{chunk_count}: {repr(chunk[:50])}...")
        
        elapsed = time.time() - start_time
        
        print(f"\n✅ Prueba completada:")
        print(f"   - Tiempo total: {elapsed:.2f}s")
        print(f"   - Chunks recibidos: {chunk_count}")
        print(f"   - Contenido total: {len(accumulated)} caracteres")
        print(f"   - Velocidad: {len(accumulated)/elapsed:.1f} chars/seg")
        print(f"   - Respuesta: {accumulated[:200]}...")
        
        return True
        
    except Exception as e:
        print(f"❌ Error en prueba: {e}")
        return False

def setup_groq_from_env():
    """Configura Groq automáticamente desde variables de entorno"""
    api_key = os.environ.get('GROQ_API_KEY')
    model = os.environ.get('GROQ_MODEL', 'llama-3.3-70b-versatile')
    
    if api_key:
        set_groq_config(api_key=api_key, model=model)
        logger.info("✅ Groq configurado desde variables de entorno")
        return True
    else:
        logger.warning("⚠️ GROQ_API_KEY no encontrada en variables de entorno")
        return False

if __name__ == "__main__":
    # Configurar logging para pruebas
    logging.basicConfig(level=logging.INFO)
    
    # Intentar configurar desde variables de entorno
    if not setup_groq_from_env():
        print("❌ Por favor configura GROQ_API_KEY como variable de entorno")
        print("   Obtén tu API key gratis en: https://console.groq.com/keys")
        exit(1)
    
    # Probar conexión
    if test_groq_connection():
        # Ejecutar prueba de streaming
        set_debug_mode(True)
        test_stream_functionality()
    else:
        print("❌ No se pudo conectar con Groq Cloud")
