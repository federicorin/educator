"""
ollama_stream.py
Módulo para manejo de streaming y comunicación con Ollama
Procesa correctamente los metadatos y extrae solo el content sin omisiones
"""

import requests
import json
import re
import time
import logging
from typing import Generator, Dict, Any, List, Optional
from datetime import datetime

# Configuración de logging
logger = logging.getLogger(__name__)

class OllamaConfig:
    """Configuración centralizada para Ollama"""
    def __init__(self, host: str = "localhost", port: int = 11434, timeout: int = 120):  # Timeout más alto para DeepSeek
        self.host = host
        self.port = port
        self.timeout = timeout
        self.base_url = f"http://{host}:{port}"
        self.generate_url = f"{self.base_url}/api/generate"
        self.chat_url = f"{self.base_url}/api/chat"
    
    def __str__(self):
        return f"OllamaConfig(host={self.host}, port={self.port}, timeout={self.timeout})"

# Instancia global de configuración (puede ser modificada)
config = OllamaConfig()

def set_ollama_config(host: str = "localhost", port: int = 11434, timeout: int = 120):
    """Configura la conexión a Ollama (timeout optimizado para DeepSeek)"""
    global config
    config = OllamaConfig(host, port, timeout)
    logger.info(f"Configuración Ollama actualizada: {config}")

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

    # Si pedimos preservar espacios finales, no usamos strip() sino que solo
    # quitamos saltos de línea finales, manteniendo espacios.
    if preserve_trailing_space:
        # eliminar únicamente \r y \n terminales, conservar espacios
        return re.sub(r'[\r\n]+$', '', limpio)
    else:
        # comportamiento previo: quitar espacios al inicio y final
        return limpio.strip()


class ContentProcessor:
    """Procesador de contenido que maneja la extracción y unión de texto"""
    
    def __init__(self):
        self.accumulated_content = ""
        self.total_chunks = 0
        self.error_count = 0
        
    def process_chunk(self, raw_chunk: str) -> Optional[str]:
        """
        Procesa un chunk individual extrayendo solo el content
        y agregando espacio al final de cada palabra completa
        """
        if not raw_chunk or not raw_chunk.strip():
            return None
            
        try:
            # Parsear JSON del chunk
            chunk_data = json.loads(raw_chunk.strip())
            
            # Extraer content según el formato de respuesta
            content = None
            
            if isinstance(chunk_data, dict):
                # Formato de chat API
                if 'message' in chunk_data and 'content' in chunk_data['message']:
                    content = chunk_data['message']['content']
                # Formato de generate API
                elif 'response' in chunk_data:
                    content = chunk_data['response']
                # Content directo
                elif 'content' in chunk_data:
                    content = chunk_data['content']
                    
                # Verificar si es el chunk final
                if chunk_data.get('done', False):
                    logger.debug(f"Chunk final recibido. Total procesados: {self.total_chunks}")
                    
            if content is not None:
                self.total_chunks += 1
                
                # 🔥 AGREGAR ESPACIO: Detectar si termina con palabra completa
                processed_content = content + " "
                
                # Acumular contenido original (sin el espacio extra para stats)
                self.accumulated_content += content
                
                # Retornar contenido con espacio para streaming
                return processed_content
                
        except json.JSONDecodeError as e:
            self.error_count += 1
            logger.warning(f"Error parseando chunk JSON: {e}, chunk: {raw_chunk[:100]}...")
            return None
        except Exception as e:
            self.error_count += 1
            logger.error(f"Error procesando chunk: {e}")
            return None
            
        return None
    
    def get_stats(self) -> Dict[str, Any]:
        """Retorna estadísticas del procesamiento"""
        return {
            'total_chunks': self.total_chunks,
            'error_count': self.error_count,
            'content_length': len(self.accumulated_content),
            'accumulated_content': self.accumulated_content
        }

def test_ollama_connection() -> bool:
    """
    Prueba la conexión con Ollama
    """
    try:
        response = requests.get(f"{config.base_url}/api/tags", timeout=5)
        if response.status_code == 200:
            logger.info("✅ Conexión con Ollama exitosa")
            return True
        else:
            logger.error(f"❌ Ollama respondió con código {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        logger.error(f"❌ No se pudo conectar a Ollama en {config.base_url}")
        return False
    except Exception as e:
        logger.error(f"❌ Error probando conexión: {e}")
        return False

def build_system_prompt(user_customize_ai: str = "", kb_context: str = "") -> str:
    """
    Construye el prompt del sistema combinando personalización y contexto
    Optimizado para DeepSeek R1 Educator
    """
    base_prompt = """Eres un asistente educativo experto basado en DeepSeek R1. Tu función es ayudar a estudiantes y educadores proporcionando explicaciones claras, detalladas y pedagógicamente sólidas. 

Características de tus respuestas:
- Explica conceptos paso a paso
- Usa ejemplos prácticos y relevantes
- Adapta el nivel de complejidad al contexto
- Fomenta el pensamiento crítico
- Proporciona recursos adicionales cuando sea apropiado"""
    
    parts = [base_prompt]
    
    if user_customize_ai.strip():
        parts.append(f"Información adicional sobre el usuario: {user_customize_ai.strip()}")
    
    if kb_context.strip():
        parts.append(f"Contexto relevante de la base de conocimientos: {kb_context.strip()}")
    
    return "\n\n".join(parts)

def prepare_messages(user_customize_ai: str, kb_context: str, prompt: str) -> List[Dict[str, str]]:
    """
    Prepara los mensajes para la API de chat de Ollama
    """
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
    model: str = "deepseek-r1:14b_educator",
    timeout: int = None
) -> Generator[str, None, None]:
    """
    Genera un stream de chat procesando correctamente los metadatos
    y extrayendo solo el content sin omisiones
    """
    if timeout is None:
        timeout = config.timeout
    
    # Verificar conexión
    if not test_ollama_connection():
        raise ConnectionError(f"No se pudo conectar a Ollama en {config.base_url}")
    
    # Preparar mensajes
    messages = prepare_messages(user_customize_ai, kb_context, prompt)
    
    # Preparar payload para la API
    payload = {
        "model": model,
        "messages": messages,
        "stream": True,
        "options": {
            "temperature": 0.8,  # Ligeramente más alta para DeepSeek
            "top_p": 0.95,       # Más diversidad para respuestas educativas
            "top_k": 50,         # Mayor variedad de tokens
            "repeat_penalty": 1.1,
            "num_ctx": 4096,     # Contexto extendido para DeepSeek
            "num_predict": -1    # Sin límite de tokens de predicción
        }
    }
    
    logger.info(f"Iniciando stream con modelo {model} hacia {config.chat_url}")
    
    # Procesador de contenido
    processor = ContentProcessor()
    
    try:
        # Realizar request con streaming
        with requests.post(
            config.chat_url,
            json=payload,
            timeout=timeout,
            stream=True
        ) as response:
            
            if response.status_code != 200:
                error_msg = f"Error HTTP {response.status_code}: {response.text}"
                logger.error(error_msg)
                raise Exception(error_msg)
            
            logger.info("Stream iniciado exitosamente")
            
            # Procesar chunks
            for line in response.iter_lines(decode_unicode=True):
                if not line or not line.strip():
                    continue
                
                # Procesar chunk y extraer content
                content = processor.process_chunk(line)
                
                # ...
                if content is not None:
    # Limpiar content antes de enviar, preservando espacio final para streaming
                    clean_content = limpiar_output(content, preserve_trailing_space=True)
                    if clean_content:  # Solo enviar si hay contenido después de limpiar
        # DEBUG opcional: ver representación con espacios
                        logger.debug(f"Chunk limpio repr: {repr(clean_content)}")
                        yield clean_content
# ...

            
            # Log de estadísticas finales
            stats = processor.get_stats()
            logger.info(f"Stream completado: {stats['total_chunks']} chunks, "
                       f"{stats['content_length']} caracteres, "
                       f"{stats['error_count']} errores")
                       
    except requests.exceptions.Timeout:
        logger.error(f"Timeout después de {timeout} segundos")
        raise TimeoutError(f"La request a Ollama excedió el timeout de {timeout} segundos")
    
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Error de conexión: {e}")
        raise ConnectionError(f"Error conectando con Ollama: {e}")
    
    except Exception as e:
        logger.error(f"Error inesperado en stream: {e}")
        raise

def chat_once(
    messages: List[Dict[str, str]],
    model: str = "deepseek-r1:14b_educator",
    timeout: int = None
) -> str:
    """
    Realiza una sola consulta a Ollama sin streaming
    Útil para tareas como resúmenes o consultas simples
    """
    if timeout is None:
        timeout = config.timeout
    
    # Verificar conexión
    if not test_ollama_connection():
        raise ConnectionError(f"No se pudo conectar a Ollama en {config.base_url}")
    
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": 0.8,  # Configuración optimizada para DeepSeek
            "top_p": 0.95,
            "top_k": 50,
            "repeat_penalty": 1.1,
            "num_ctx": 4096,
            "num_predict": -1
        }
    }
    
    logger.info(f"Realizando consulta única con modelo {model}")
    
    try:
        response = requests.post(
            config.chat_url,
            json=payload,
            timeout=timeout
        )
        
        if response.status_code != 200:
            error_msg = f"Error HTTP {response.status_code}: {response.text}"
            logger.error(error_msg)
            raise Exception(error_msg)
        
        result = response.json()
        
        # Extraer content de la respuesta
        if 'message' in result and 'content' in result['message']:
            content = result['message']['content']
        elif 'response' in result:
            content = result['response']
        else:
            logger.warning(f"Formato de respuesta inesperado: {result}")
            content = str(result)
        
        # Limpiar y retornar
        clean_content = limpiar_output(content)
        logger.info(f"Consulta única completada: {len(clean_content)} caracteres")
        
        return clean_content
        
    except requests.exceptions.Timeout:
        logger.error(f"Timeout después de {timeout} segundos")
        raise TimeoutError(f"La request a Ollama excedió el timeout de {timeout} segundos")
    
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Error de conexión: {e}")
        raise ConnectionError(f"Error conectando con Ollama: {e}")
    
    except Exception as e:
        logger.error(f"Error inesperado: {e}")
        raise

def set_debug_mode(enabled: bool = True):
    """
    Habilita/deshabilita el modo debug para logging detallado
    """
    level = logging.DEBUG if enabled else logging.INFO
    logging.getLogger(__name__).setLevel(level)
    logger.info(f"Modo debug {'habilitado' if enabled else 'deshabilitado'}")

def get_available_models() -> List[str]:
    """
    Obtiene la lista de modelos disponibles en Ollama
    """
    try:
        response = requests.get(f"{config.base_url}/api/tags", timeout=10)
        if response.status_code == 200:
            data = response.json()
            models = [model['name'] for model in data.get('models', [])]
            logger.info(f"Modelos disponibles: {models}")
            return models
        else:
            logger.error(f"Error obteniendo modelos: HTTP {response.status_code}")
            return []
    except Exception as e:
        logger.error(f"Error conectando para obtener modelos: {e}")
        return []

# Función de utilidad para testing
def test_stream_functionality(prompt: str = "Explica el concepto de fotosíntesis de manera didáctica", model: str = "deepseek-r1:14b_educator"):
    """
    Función de prueba para verificar que el streaming funciona correctamente
    """
    print(f"🧪 Probando streaming con prompt: '{prompt}'")
    print(f"🔧 Configuración: {config}")
    
    try:
        accumulated = ""
        chunk_count = 0
        
        for chunk in stream_chat_for_user(prompt=prompt, model=model):
            accumulated += chunk
            chunk_count += 1
            print(f"Chunk #{chunk_count}: {repr(chunk)}")
        
        print(f"\n✅ Prueba completada:")
        print(f"   - Chunks recibidos: {chunk_count}")
        print(f"   - Contenido total: {len(accumulated)} caracteres")
        print(f"   - Respuesta: {accumulated[:200]}...")
        
        return True
        
    except Exception as e:
        print(f"❌ Error en prueba: {e}")
        return False

if __name__ == "__main__":
    # Configurar logging para pruebas
    logging.basicConfig(level=logging.INFO)
    
    # Configurar Ollama (ajustar según tu setup)
    set_ollama_config(host="localhost", port=11434, timeout=120)  # Timeout más alto para DeepSeek
    
    # Ejecutar prueba
    set_debug_mode(True)
    test_stream_functionality()