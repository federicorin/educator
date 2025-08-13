"""
ollama_stream.py - MODIFICADO PARA GROQ - INICIALIZACIÓN LAZY
Módulo para manejo de streaming usando EXCLUSIVAMENTE Groq Cloud
Llama 3.3 70B en todos los casos (local y producción)
VERSION SIN LIMPIEZA DE RESPUESTAS - La IA responde tal como genera
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
    def __init__(self, api_key: Optional[str] = None, model: str = "meta-llama/llama-4-maverick-17b-128e-instruct"):
        self.api_key = api_key or os.environ.get('GROQ_API_KEY')
        self.model = model
        if not self.api_key:
            raise ValueError("GROQ_API_KEY requerida. Obtén una gratis en https://console.groq.com/keys")
    
    def __str__(self):
        masked_key = f"{self.api_key[:8]}..." if self.api_key else "None"
        return f"GroqConfig(model={self.model}, api_key={masked_key})"

# 🔥 CAMBIO CRÍTICO: NO inicializar automáticamente
config = None

def get_config():
    """Obtiene la configuración, inicializándola si es necesario"""
    global config
    if config is None:
        # Intentar configurar desde variables de entorno
        api_key = os.environ.get('GROQ_API_KEY')
        if not api_key:
            # Si no hay API key, dar instrucciones claras
            raise ValueError(
                "❌ GROQ_API_KEY no configurada.\n"
                "💡 Soluciones:\n"
                "   1. Configura variable de entorno: export GROQ_API_KEY='tu_api_key'\n"
                "   2. O usa: set_groq_config('tu_api_key')\n"
                "   3. Obtén API key gratis en: https://console.groq.com/keys"
            )
        config = GroqConfig(api_key=api_key)
        logger.info(f"✅ Groq configurado automáticamente: {config}")
    return config

def set_groq_config(api_key: Optional[str] = None, model: str = "meta-llama/llama-4-maverick-17b-128e-instruct"):
    """Configura la conexión a Groq Cloud"""
    global config
    config = GroqConfig(api_key=api_key, model=model)
    logger.info(f"Configuración Groq actualizada: {config}")

# 🚫 FUNCIÓN DESHABILITADA - NO SE USA MÁS
def limpiar_output(texto: str, preserve_trailing_space: bool = False) -> str:
    """
    FUNCIÓN DESHABILITADA - Ahora retorna el texto sin modificar
    """
    # ✅ CAMBIO PRINCIPAL: Retornar texto original sin modificaciones
    return texto if texto else ""

class GroqClient:
    """Cliente unificado para Groq Cloud"""
    
    def __init__(self):
        self.config = get_config()  # 🔥 CAMBIO: usar get_config()
        self.client = Groq(api_key=self.config.api_key)
    
    def chat_completion(self, messages: List[Dict[str, str]], temperature: float = 0.8) -> str:
        """Completa un chat sin streaming usando Groq"""
        try:
            completion = self.client.chat.completions.create(
                model=self.config.model,
                messages=messages,
                temperature=temperature,
                max_completion_tokens=4096,  # Generoso para respuestas educativas
                top_p=0.95,
                stream=False,
                stop=None
            )
            
            response = completion.choices[0].message.content
            # ✅ CAMBIO: NO limpiar la respuesta, devolverla tal como viene
            return response if response else ""
            
        except Exception as e:
            logger.error(f"Error en Groq completion: {e}")
            raise
    
    def stream_completion(self, messages: List[Dict[str, str]], temperature: float = 0.8) -> Generator[str, None, None]:
        """Stream de chat usando Groq Cloud"""
        try:
            completion = self.client.chat.completions.create(
                model=self.config.model,
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
                    # ✅ CAMBIO CRÍTICO: NO limpiar chunks, enviar tal como vienen
                    yield content
                        
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
    ✅ VERSION SIN LIMPIEZA - Respuestas tal como las genera la IA
    """
    if not prompt.strip():
        yield "Error: El prompt no puede estar vacío."
        return
    
    # Preparar mensajes
    messages = prepare_messages(user_customize_ai, kb_context, prompt)
    
    try:
        current_config = get_config()  # 🔥 CAMBIO: obtener config dinámicamente
        logger.info(f"🚀 Iniciando stream con Groq Cloud - Modelo: {current_config.model}")
        
        groq_client = GroqClient()
        
        for chunk in groq_client.stream_completion(messages):
            if chunk:
                # ✅ CAMBIO: Enviar chunks sin modificar
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
    ✅ VERSION SIN LIMPIEZA - Respuesta tal como la genera la IA
    """
    try:
        current_config = get_config()  # 🔥 CAMBIO: obtener config dinámicamente
        logger.info(f"💬 Consulta única con Groq Cloud - Modelo: {current_config.model}")
        
        groq_client = GroqClient()
        response = groq_client.chat_completion(messages)
        
        logger.info(f"✅ Consulta completada: {len(response)} caracteres")
        # ✅ CAMBIO: Retornar respuesta sin limpiar
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
        "meta-llama/llama-4-maverick-17b-128e-instruct",    # 🎯 Recomendado (default)
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
    ✅ VERSION SIN LIMPIEZA - Respuesta original de la IA
    """
    try:
        messages = [{"role": "user", "content": prompt}]
        response = chat_once(messages)
        # ✅ CAMBIO: Retornar respuesta sin modificar
        return response
    except Exception as e:
        logger.error(f"Error en ollama_run_for_kb: {e}")
        return f"⚠️ Error al procesar consulta: {e}"

# FUNCIONES DE UTILIDAD Y TESTING

def test_stream_functionality(prompt: str = "Explica el concepto de fotosíntesis de manera didáctica para estudiantes de secundaria"):
    """Función de prueba para verificar que el streaming funciona correctamente"""
    try:
        current_config = get_config()
        print(f"🧪 Probando streaming Groq con prompt: '{prompt}'")
        print(f"🔧 Modelo configurado: {current_config.model}")
        print(f"🔑 API Key: {current_config.api_key[:8]}...")
        print("✅ MODO SIN LIMPIEZA ACTIVADO - Respuestas originales de la IA")
        
        accumulated = ""
        chunk_count = 0
        start_time = time.time()
        
        for chunk in stream_chat_for_user(prompt=prompt):
            accumulated += chunk
            chunk_count += 1
            # Mostrar chunk completo sin modificar para debugging
            print(f"Chunk #{chunk_count}: {repr(chunk)}")
        
        elapsed = time.time() - start_time
        
        print(f"\n✅ Prueba completada:")
        print(f"   - Tiempo total: {elapsed:.2f}s")
        print(f"   - Chunks recibidos: {chunk_count}")
        print(f"   - Contenido total: {len(accumulated)} caracteres")
        print(f"   - Velocidad: {len(accumulated)/elapsed:.1f} chars/seg")
        print(f"   - Respuesta completa:\n{accumulated}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error en prueba: {e}")
        return False

def setup_groq_from_env():
    """Configura Groq automáticamente desde variables de entorno"""
    api_key = os.environ.get('GROQ_API_KEY')
    model = os.environ.get('GROQ_MODEL', 'meta-llama/llama-4-maverick-17b-128e-instruct')
    
    if api_key:
        set_groq_config(api_key=api_key, model=model)
        logger.info("✅ Groq configurado desde variables de entorno")
        return True
    else:
        logger.warning("⚠️ GROQ_API_KEY no encontrada en variables de entorno")
        return False

def is_groq_configured() -> bool:
    """Verifica si Groq está configurado sin lanzar excepción"""
    try:
        get_config()
        return True
    except ValueError:
        return False

def get_groq_status() -> dict:
    """Obtiene el estado actual de la configuración de Groq"""
    try:
        current_config = get_config()
        return {
            "configured": True,
            "model": current_config.model,
            "api_key_present": bool(current_config.api_key),
            "api_key_preview": current_config.api_key[:8] + "..." if current_config.api_key else "None",
            "cleaning_disabled": True  # ✅ Nueva propiedad
        }
    except ValueError as e:
        return {
            "configured": False,
            "error": str(e),
            "model": None,
            "api_key_present": False,
            "cleaning_disabled": True  # ✅ Nueva propiedad
        }

if __name__ == "__main__":
    # Configurar logging para pruebas
    logging.basicConfig(level=logging.INFO)
    
    # Verificar estado de configuración
    status = get_groq_status()
    print(f"🔍 Estado de Groq: {status}")
    
    if not status["configured"]:
        print("❌ Groq no está configurado")
        print("💡 Configura GROQ_API_KEY como variable de entorno")
        print("   Obtén tu API key gratis en: https://console.groq.com/keys")
        
        # Ejemplo de cómo configurar manualmente
        print("\n🛠️ Para configurar manualmente:")
        print("   set_groq_config('tu_api_key_aqui')")
        exit(1)
    
    # Probar conexión
    if test_groq_connection():
        # Ejecutar prueba de streaming
        set_debug_mode(True)
        test_stream_functionality()
    else:
        print("❌ No se pudo conectar con Groq Cloud")
