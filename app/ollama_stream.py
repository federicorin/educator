""" 
ollama_stream.py - MODIFICADO PARA GROQ - INICIALIZACIÓN LAZY + PERSONALIDAD DESDE .ENV
Módulo para manejo de streaming usando EXCLUSIVAMENTE Groq Cloud 
Llama 3.3 70B con personalidad configurable desde variables de entorno
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

# NUEVA IMPORTACIÓN: Para cargar .env
try:
    from dotenv import load_dotenv
    load_dotenv()  # Cargar variables de entorno desde .env
except ImportError:
    # Si python-dotenv no está instalado, continuar sin él
    pass

# Configuración de logging 
logger = logging.getLogger(__name__) 

class PersonalityConfig:
    """Configuración de personalidad desde variables de entorno"""
    
    def __init__(self):
        # Cargar configuración de personalidad desde .env
        self.ai_name = os.environ.get('AI_NAME', 'Asistente IA')
        self.ai_role = os.environ.get('AI_ROLE', 'asistente educativo experto')
        self.ai_personality = os.environ.get('AI_PERSONALITY', 'amigable, profesional y pedagógico')
        self.ai_expertise = os.environ.get('AI_EXPERTISE', 'educación, explicaciones didácticas y resolución de problemas')
        self.ai_tone = os.environ.get('AI_TONE', 'claro, accesible y motivador')
        self.ai_language_style = os.environ.get('AI_LANGUAGE_STYLE', 'profesional pero cercano')
        self.ai_response_format = os.environ.get('AI_RESPONSE_FORMAT', 'estructurado con ejemplos prácticos')
        
        # Configuraciones adicionales
        self.ai_max_tokens = int(os.environ.get('AI_MAX_TOKENS', '4096'))
        self.ai_temperature = float(os.environ.get('AI_TEMPERATURE', '0.8'))
        self.ai_system_context = os.environ.get('AI_SYSTEM_CONTEXT', '')
        self.ai_custom_instructions = os.environ.get('AI_CUSTOM_INSTRUCTIONS', '')
        
        # Configuraciones educativas específicas
        self.education_level = os.environ.get('EDUCATION_LEVEL', 'adaptativo')
        self.learning_style = os.environ.get('LEARNING_STYLE', 'visual y práctico')
        self.feedback_style = os.environ.get('FEEDBACK_STYLE', 'constructivo y motivacional')
        
    def to_dict(self) -> Dict[str, Any]:
        """Convierte la configuración a diccionario"""
        return {
            'ai_name': self.ai_name,
            'ai_role': self.ai_role,
            'ai_personality': self.ai_personality,
            'ai_expertise': self.ai_expertise,
            'ai_tone': self.ai_tone,
            'ai_language_style': self.ai_language_style,
            'ai_response_format': self.ai_response_format,
            'ai_max_tokens': self.ai_max_tokens,
            'ai_temperature': self.ai_temperature,
            'ai_system_context': self.ai_system_context,
            'ai_custom_instructions': self.ai_custom_instructions,
            'education_level': self.education_level,
            'learning_style': self.learning_style,
            'feedback_style': self.feedback_style,
        }
    
    def __str__(self):
        return f"PersonalityConfig(name='{self.ai_name}', role='{self.ai_role}', temp={self.ai_temperature})"

class GroqConfig: 
    """Configuración centralizada para Groq Cloud""" 
    def __init__(self, api_key: Optional[str] = None, model: str = "meta-llama/llama-4-maverick-17b-128e-instruct"): 
        self.api_key = api_key or os.environ.get('GROQ_API_KEY') 
        self.model = model or os.environ.get('GROQ_MODEL', 'meta-llama/llama-4-maverick-17b-128e-instruct')
        
        if not self.api_key: 
            raise ValueError("GROQ_API_KEY requerida. Obtén una gratis en https://console.groq.com/keys") 
     
    def __str__(self): 
        masked_key = f"{self.api_key[:8]}..." if self.api_key else "None" 
        return f"GroqConfig(model={self.model}, api_key={masked_key})" 

# 🔥 CAMBIO CRÍTICO: NO inicializar automáticamente 
config = None 
personality_config = None

def get_personality_config() -> PersonalityConfig:
    """Obtiene la configuración de personalidad, inicializándola si es necesario"""
    global personality_config
    if personality_config is None:
        personality_config = PersonalityConfig()
        logger.info(f"✅ Personalidad configurada: {personality_config}")
    return personality_config

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
                "   1. Configura en .env: GROQ_API_KEY=tu_api_key\n" 
                "   2. Configura variable de entorno: export GROQ_API_KEY='tu_api_key'\n" 
                "   3. O usa: set_groq_config('tu_api_key')\n" 
                "   4. Obtén API key gratis en: https://console.groq.com/keys" 
            ) 
        config = GroqConfig(api_key=api_key) 
        logger.info(f"✅ Groq configurado automáticamente: {config}") 
    return config 
 
def set_groq_config(api_key: Optional[str] = None, model: str = None): 
    """Configura la conexión a Groq Cloud""" 
    global config
    if model is None:
        model = os.environ.get('GROQ_MODEL', 'meta-llama/llama-4-maverick-17b-128e-instruct')
    
    config = GroqConfig(api_key=api_key, model=model) 
    logger.info(f"Configuración Groq actualizada: {config}") 

def reload_personality_config():
    """Recarga la configuración de personalidad desde las variables de entorno"""
    global personality_config
    personality_config = PersonalityConfig()
    logger.info(f"🔄 Personalidad recargada: {personality_config}")
    return personality_config

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
        self.personality = get_personality_config()  # 🆕 NUEVO: cargar personalidad
        self.client = Groq(api_key=self.config.api_key) 
     
    def chat_completion(self, messages: List[Dict[str, str]], temperature: float = None) -> str: 
        """Completa un chat sin streaming usando Groq""" 
        # Usar temperatura de personalidad si no se especifica
        if temperature is None:
            temperature = self.personality.ai_temperature
            
        try: 
            completion = self.client.chat.completions.create( 
                model=self.config.model, 
                messages=messages, 
                temperature=temperature, 
                max_completion_tokens=self.personality.ai_max_tokens,  # 🆕 Configurable
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
     
    def stream_completion(self, messages: List[Dict[str, str]], temperature: float = None) -> Generator[str, None, None]: 
        """Stream de chat usando Groq Cloud""" 
        # Usar temperatura de personalidad si no se especifica
        if temperature is None:
            temperature = self.personality.ai_temperature
            
        try: 
            completion = self.client.chat.completions.create( 
                model=self.config.model, 
                messages=messages, 
                temperature=temperature, 
                max_completion_tokens=self.personality.ai_max_tokens,  # 🆕 Configurable
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
    Construye el prompt del sistema combinando personalidad desde .env y contexto 
    🆕 NUEVO: Integra configuración de personalidad completa
    """ 
    personality = get_personality_config()
    
    # Prompt base personalizado desde configuración
    base_prompt = f"""Eres {personality.ai_name}, un {personality.ai_role}. 

Tu personalidad es: {personality.ai_personality}
Tu especialidad: {personality.ai_expertise}
Tu tono de comunicación: {personality.ai_tone}
Tu estilo de lenguaje: {personality.ai_language_style}
Formato de respuestas: {personality.ai_response_format}

Configuración educativa:
- Nivel educativo: {personality.education_level}
- Estilo de aprendizaje preferido: {personality.learning_style}  
- Estilo de feedback: {personality.feedback_style}

Características de tus respuestas: 
- Explica conceptos paso a paso con ejemplos prácticos 
- Adapta el nivel de complejidad al contexto del usuario 
- Fomenta el pensamiento crítico y la curiosidad 
- Proporciona recursos adicionales cuando sea apropiado 
- Usa un lenguaje claro y accesible 
- Estructura la información de manera lógica y fácil de seguir"""

    parts = [base_prompt]
    
    # Agregar contexto del sistema si existe
    if personality.ai_system_context.strip():
        parts.append(f"Contexto adicional del sistema: {personality.ai_system_context.strip()}")
    
    # Agregar instrucciones personalizadas si existen
    if personality.ai_custom_instructions.strip():
        parts.append(f"Instrucciones específicas: {personality.ai_custom_instructions.strip()}")
     
    if user_customize_ai.strip(): 
        parts.append(f"Personalización del usuario: {user_customize_ai.strip()}") 
     
    if kb_context.strip(): 
        parts.append(f"Información relevante de la base de conocimientos: {kb_context.strip()}") 
     
    return "\n\n".join(parts) 

def prepare_messages(user_customize_ai: str, kb_context: str, prompt: str) -> List[Dict[str, str]]: 
    """Prepara los mensajes para la API de Groq con personalidad desde .env""" 
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
    🆕 NUEVO: Con personalidad configurable desde .env
    """ 
    if not prompt.strip(): 
        yield "Error: El prompt no puede estar vacío." 
        return 
     
    # Preparar mensajes con personalidad
    messages = prepare_messages(user_customize_ai, kb_context, prompt) 
     
    try: 
        current_config = get_config()  # 🔥 CAMBIO: obtener config dinámicamente 
        personality = get_personality_config()  # 🆕 NUEVO: obtener personalidad
        logger.info(f"🚀 Iniciando stream con Groq Cloud - Modelo: {current_config.model}")
        logger.info(f"🎭 Personalidad: {personality.ai_name} ({personality.ai_role})")
         
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
    🆕 NUEVO: Con personalidad configurable desde .env
    """ 
    try: 
        current_config = get_config()  # 🔥 CAMBIO: obtener config dinámicamente 
        personality = get_personality_config()  # 🆕 NUEVO: obtener personalidad
        logger.info(f"💬 Consulta única con Groq Cloud - Modelo: {current_config.model}") 
        logger.info(f"🎭 Personalidad: {personality.ai_name}")
         
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

# Función especial para KnowledgeB
def ollama_run_for_kb(model: str, prompt: str) -> str:
    """
    Función para reemplazar subprocess en KnowledgeBase 
    ✅ ARREGLADO: Ahora respeta el parámetro modelo
    """
    try: 
        # Crear cliente con modelo específico
        temp_config = GroqConfig(model=model)
        client = Groq(api_key=temp_config.api_key)
        
        messages = [{"role": "user", "content": prompt}]
        
        completion = client.chat.completions.create(
            model=model,  # ← Usar el modelo especificado
            messages=messages,
            temperature=0.7,
            max_completion_tokens=4096
        )
        
        response = completion.choices[0].message.content
        return response if response else ""
        
    except Exception as e: 
        logger.error(f"Error en ollama_run_for_kb: {e}") 
        return f"⚠️ Error al procesar consulta: {e}"

# 🆕 NUEVAS FUNCIONES DE GESTIÓN DE PERSONALIDAD

def get_personality_summary() -> Dict[str, Any]:
    """Obtiene un resumen de la configuración de personalidad actual"""
    try:
        personality = get_personality_config()
        return {
            "configured": True,
            "summary": personality.to_dict(),
            "ai_name": personality.ai_name,
            "ai_role": personality.ai_role,
            "temperature": personality.ai_temperature,
            "max_tokens": personality.ai_max_tokens
        }
    except Exception as e:
        return {
            "configured": False,
            "error": str(e),
            "summary": {}
        }

def update_personality_from_env():
    """Fuerza la recarga de personalidad desde variables de entorno"""
    global personality_config
    personality_config = None
    return get_personality_config()

def print_current_personality():
    """Imprime la configuración actual de personalidad de forma legible"""
    personality = get_personality_config()
    
    print("🎭 CONFIGURACIÓN DE PERSONALIDAD ACTUAL:")
    print("="*50)
    for key, value in personality.to_dict().items():
        if value and value != 'None':  # Solo mostrar valores configurados
            print(f"  {key.replace('_', ' ').title()}: {value}")
    print("="*50)

# FUNCIONES DE UTILIDAD Y TESTING 

def test_stream_functionality(prompt: str = "Explica el concepto de fotosíntesis de manera didáctica para estudiantes de secundaria"): 
    """Función de prueba para verificar que el streaming funciona correctamente""" 
    try: 
        current_config = get_config()
        personality = get_personality_config()
        print(f"🧪 Probando streaming Groq con prompt: '{prompt}'") 
        print(f"🔧 Modelo configurado: {current_config.model}") 
        print(f"🔑 API Key: {current_config.api_key[:8]}...") 
        print(f"🎭 Personalidad: {personality.ai_name} - {personality.ai_role}")
        print(f"🌡️ Temperatura: {personality.ai_temperature}")
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
        personality = get_personality_config()
        return { 
            "configured": True, 
            "model": current_config.model, 
            "api_key_present": bool(current_config.api_key), 
            "api_key_preview": current_config.api_key[:8] + "..." if current_config.api_key else "None", 
            "cleaning_disabled": True,  # ✅ Nueva propiedad
            "personality": {  # 🆕 Información de personalidad
                "ai_name": personality.ai_name,
              

