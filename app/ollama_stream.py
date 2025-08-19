# == file: ollama_stream.py ==
"""
Trimmed Groq/Ollama bridge.
Key changes:
- Safe import of the external SDK.
- Provides a single function ollama_run_for_kb(query, namespace, top_k) used by KB code.
- Defensive programming and optional retry.

This file intentionally keeps the interface minimal so routes.py can stream easily.
"""

import time
import logging
import os
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

try:
    # Lazy import guard; if groq is missing the module still imports fine.
    from groq import Groq  # type: ignore
except Exception:
    Groq = None

class GroqClientWrapper:
    def __init__(self, api_key: Optional[str] = None):  # ✅ Corregido: __init__
        if Groq is None:
            raise RuntimeError("groq SDK is not installed")
        
        # Si no se pasa API key, intentar obtenerla de variable de entorno
        if api_key is None:
            api_key = os.getenv('GROQ_API_KEY')
        
        if not api_key:
            raise RuntimeError("GROQ_API_KEY not found in environment variables or parameters")
            
        self._api_key = api_key
        self.client = Groq(api_key=api_key)

    def search(self, prompt: str, top_k: int = 5) -> List[Dict]:
        # Usar las variables de entorno para personalizar el prompt
        ai_name = os.getenv("AI_NAME", "Asistente IA")
        ai_institution = os.getenv("AI_INSTITUTION", "")
        ai_description = os.getenv("AI_DESCRIPTION", "Soy un asistente útil")
        ai_style = os.getenv("AI_RESPONDER_STYLE", "claro y conciso")
        
        system_prompt = f"Eres {ai_name}"
        if ai_institution:
            system_prompt += f" de {ai_institution}"
        system_prompt += f". {ai_description}. Respondes de manera {ai_style} y siempre en español."
        
        resp = self.client.chat.completions.create(
            model="meta-llama/llama-4-maverick-17b-128e-instruct",  # o el modelo que uses
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            max_tokens=1000000,
            temperature=1.4,  # Un poco más de creatividad
        )
        # The response parsing depends on the model -- here we keep it permissive
        if isinstance(resp, str):
            return [{"id": "groq_1", "text": resp}]
        
        # Si la respuesta tiene estructura de OpenAI/Groq
        if hasattr(resp, 'choices') and resp.choices:
            content = resp.choices[0].message.content
            return [{"id": "groq_1", "text": content}]
        
        return [{"id": "groq_1", "text": str(resp)}]

# Public helper used by KnowledgeBase
def ollama_run_for_kb(query: str, namespace: str = "default", top_k: int = 5):
    # If Groq not available, raise to allow fallback in caller
    if Groq is None:
        raise RuntimeError("Groq SDK not available; install the 'groq' package to enable semantic search")

    # create client with env var inside if needed (kept simple here)
    try:
        client = GroqClientWrapper()  # ✅ Ahora buscará GROQ_API_KEY automáticamente
    except RuntimeError as e:
        logger.error("Failed to initialize Groq client: %s", e)
        raise
    
    try:
        # small retry loop
        for attempt in range(2):
            try:
                return client.search(query, top_k=top_k)
            except Exception as e:
                logger.warning("Groq search attempt %s failed: %s", attempt + 1, e)
                time.sleep(0.5 * (attempt + 1))
        # final attempt
        return client.search(query, top_k=top_k)
    except Exception as e:
        logger.exception("Groq bridge failed: %s", e)
        raise