# knowledge_base.py - ADAPTADO PARA GROQ

import os
import json
import logging
from datetime import datetime
from .ollama_stream import ollama_run_for_kb  # ✅ Ahora usa Groq internamente

# Configurar logging
logger = logging.getLogger(__name__)

class KnowledgeBase:
    def __init__(self, namespace="global"):
        self.namespace = namespace
        self.db_folder = os.path.join("vector_store", self.namespace)
        os.makedirs(self.db_folder, exist_ok=True)
        self.index_file = os.path.join(self.db_folder, "index.json")
        self.documents = []
        self.load_documents()
        
        logger.info(f"KnowledgeBase inicializada - Namespace: {self.namespace}, Documentos: {len(self.documents)}")

    def load_documents(self):
        """Carga los documentos desde el archivo de índice"""
        try:
            if os.path.exists(self.index_file):
                with open(self.index_file, "r", encoding="utf-8") as f:
                    self.documents = json.load(f)
                logger.info(f"✅ Cargados {len(self.documents)} documentos")
            else:
                self.documents = []
                logger.info("📝 Iniciando con base de conocimientos vacía")
        except Exception as e:
            logger.error(f"❌ Error cargando documentos: {e}")
            self.documents = []

    def save_documents(self):
        """Guarda los documentos en el archivo de índice"""
        try:
            with open(self.index_file, "w", encoding="utf-8") as f:
                json.dump(self.documents, f, ensure_ascii=False, indent=2)
            logger.debug(f"💾 Guardados {len(self.documents)} documentos")
        except Exception as e:
            logger.error(f"❌ Error guardando documentos: {e}")

    def add_document(self, text):
        """Agrega un nuevo documento a la base de conocimientos"""
        if text and text.strip():  # Validación básica
            self.documents.append(text.strip())
            self.save_documents()
            logger.info(f"➕ Documento agregado. Total: {len(self.documents)}")
            return True
        logger.warning("⚠️ Intento de agregar documento vacío")
        return False

    def remove_document(self, index):
        """Remueve un documento por índice"""
        if 0 <= index < len(self.documents):
            removed = self.documents.pop(index)
            self.save_documents()
            logger.info(f"🗑️ Documento removido en índice {index}")
            return removed
        logger.warning(f"⚠️ Índice {index} fuera de rango")
        return None

    def get_document_count(self):
        """Retorna el número total de documentos"""
        return len(self.documents)

    def retrieve_relevant_documents(self, query, max_docs=3):
        """
        Usa Groq Cloud (Llama 3.3 70B) para encontrar documentos relevantes
        """
        if not self.documents:
            return "📭 No hay documentos en la base de conocimientos."
        
        if not query.strip():
            return "⚠️ Consulta vacía."

        # 🎯 PROMPT OPTIMIZADO PARA LLAMA 3.3 70B
        prompt = f"""Eres un sistema de recuperación de información inteligente. Tu tarea es analizar una base de conocimientos y encontrar la información más relevante para responder una pregunta específica.

**BASE DE CONOCIMIENTOS:**
{self._format_documents_for_analysis()}

**PREGUNTA DEL USUARIO:**
{query}

**INSTRUCCIONES:**
1. Analiza cada documento en la base de conocimientos
2. Identifica cuáles son más relevantes para la pregunta
3. Selecciona máximo {max_docs} documentos más relevantes
4. Crea un resumen conciso que combine la información relevante
5. Si no encuentras información relevante, dilo claramente

**FORMATO DE RESPUESTA:**
Proporciona un resumen claro y directo de la información relevante encontrada, organizando los puntos principales de manera lógica."""

        try:
            logger.info(f"🔍 Buscando documentos relevantes para: '{query[:50]}...'")
            # ✅ Esta función ahora usa Groq Cloud internamente
            result = ollama_run_for_kb("llama-3.3-70b-versatile", prompt)
            
            if result and result.strip():
                logger.info(f"✅ Documentos relevantes encontrados: {len(result)} chars")
                return result.strip()
            else:
                return "❌ No se pudo procesar la consulta."
            
        except Exception as e:
            error_msg = f"⚠️ Error al buscar contexto relevante: {e}"
            logger.error(error_msg)
            return error_msg

    def _format_documents_for_analysis(self):
        """Formatea documentos para análisis, evitando problemas de contexto"""
        if not self.documents:
            return "No hay documentos disponibles."
        
        formatted_docs = []
        max_doc_length = 800  # Límite para evitar exceder contexto
        
        for i, doc in enumerate(self.documents, 1):
            truncated_doc = doc[:max_doc_length] + "..." if len(doc) > max_doc_length else doc
            formatted_docs.append(f"DOCUMENTO {i}:\n{truncated_doc}")
        
        return "\n\n".join(formatted_docs)

    def search_documents(self, search_term):
        """Búsqueda simple por texto en los documentos"""
        if not search_term.strip():
            return []
        
        search_term = search_term.lower()
        matching_docs = []
        
        for i, doc in enumerate(self.documents):
            if search_term in doc.lower():
                matching_docs.append({
                    'index': i,
                    'document': doc,
                    'preview': doc[:200] + "..." if len(doc) > 200 else doc
                })
        
        logger.info(f"🔍 Búsqueda '{search_term}': {len(matching_docs)} documentos encontrados")
        return matching_docs

    def get_all_documents(self):
        """Retorna todos los documentos con sus índices"""
        return [{'index': i, 'document': doc} for i, doc in enumerate(self.documents)]

    def update_document(self, index, new_text):
        """Actualiza un documento existente"""
        if 0 <= index < len(self.documents) and new_text.strip():
            old_text = self.documents[index][:50] + "..."
            self.documents[index] = new_text.strip()
            self.save_documents()
            logger.info(f"✏️ Documento {index} actualizado: '{old_text}' → '{new_text[:50]}...'")
            return True
        return False

    def clear_all_documents(self):
        """Elimina todos los documentos"""
        count = len(self.documents)
        self.documents = []
        self.save_documents()
        logger.info(f"🧹 Base de conocimientos limpiada: {count} documentos eliminados")

    def export_knowledge_base(self, filepath):
        """Exporta la base de conocimientos a un archivo JSON"""
        try:
            export_data = {
                'namespace': self.namespace,
                'document_count': len(self.documents),
                'documents': self.documents,
                'exported_at': datetime.now().isoformat(),
                'version': '1.0'
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"📤 Base de conocimientos exportada a: {filepath}")
            return True
        except Exception as e:
            logger.error(f"❌ Error exportando: {e}")
            return False

    def import_knowledge_base(self, filepath, avoid_duplicates=True):
        """Importa una base de conocimientos desde un archivo JSON"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                import_data = json.load(f)
            
            if 'documents' in import_data:
                imported_docs = import_data['documents']
                added_count = 0
                
                for doc in imported_docs:
                    if doc.strip():
                        if not avoid_duplicates or doc not in self.documents:
                            self.documents.append(doc.strip())
                            added_count += 1
                
                self.save_documents()
                logger.info(f"📥 Importados {added_count} documentos desde: {filepath}")
                return added_count
            return 0
        except Exception as e:
            logger.error(f"❌ Error importando: {e}")
            return 0

    def get_knowledge_stats(self):
        """Retorna estadísticas de la base de conocimientos"""
        if not self.documents:
            return {
                'total_documents': 0,
                'total_characters': 0,
                'total_words': 0,
                'average_document_length': 0,
                'namespace': self.namespace
            }
        
        total_chars = sum(len(doc) for doc in self.documents)
        total_words = sum(len(doc.split()) for doc in self.documents)
        
        return {
            'total_documents': len(self.documents),
            'total_characters': total_chars,
            'total_words': total_words,
            'average_document_length': total_chars // len(self.documents),
            'namespace': self.namespace,
            'storage_path': self.db_folder
        }

    def semantic_search(self, query, max_results=5):
        """
        Búsqueda semántica usando Groq para entender el contexto
        Más inteligente que búsqueda por keywords
        """
        if not self.documents or not query.strip():
            return []

        prompt = f"""Eres un sistema de búsqueda semántica. Analiza estos documentos y clasifícalos por relevancia semántica a la consulta.

**DOCUMENTOS:**
{json.dumps([{'id': i, 'content': doc} for i, doc in enumerate(self.documents)], ensure_ascii=False, indent=2)}

**CONSULTA:** {query}

**TAREA:**
1. Analiza la intención y el contexto de la consulta
2. Evalúa la relevancia semántica de cada documento
3. Clasifica los documentos por relevancia (más relevante primero)
4. Retorna máximo {max_results} documentos más relevantes

**FORMATO DE RESPUESTA:**
Responde SOLO con una lista de IDs de documentos ordenados por relevancia, separados por comas.
Ejemplo: 2,0,5,1
Si ningún documento es relevante, responde: ninguno"""

        try:
            logger.info(f"🧠 Búsqueda semántica: '{query[:50]}...'")
            result = ollama_run_for_kb("llama-3.3-70b-versatile", prompt)
            
            if result.strip().lower() == "ninguno":
                logger.info("❌ Búsqueda semántica: sin resultados relevantes")
                return []
            
            # Parsear IDs de documentos
            doc_ids = []
            for id_str in result.strip().split(','):
                try:
                    doc_id = int(id_str.strip())
                    if 0 <= doc_id < len(self.documents):
                        doc_ids.append(doc_id)
                except ValueError:
                    continue
            
            # Retornar documentos ordenados por relevancia
            relevant_docs = []
            for doc_id in doc_ids[:max_results]:
                relevant_docs.append({
                    'index': doc_id,
                    'document': self.documents[doc_id],
                    'preview': self.documents[doc_id][:200] + "..." if len(self.documents[doc_id]) > 200 else self.documents[doc_id],
                    'relevance_rank': len(relevant_docs) + 1
                })
            
            logger.info(f"✅ Búsqueda semántica: {len(relevant_docs)} documentos relevantes")
            return relevant_docs
            
        except Exception as e:
            logger.error(f"❌ Error en búsqueda semántica: {e}")
            # Fallback a búsqueda simple
            return self.search_documents(query)[:max_results]

    def find_similar_documents(self, reference_text, max_results=3):
        """
        Encuentra documentos similares al texto de referencia usando análisis semántico
        """
        if not self.documents or not reference_text.strip():
            return []

        prompt = f"""Analiza este texto de referencia y encuentra los documentos más similares semánticamente:

**TEXTO DE REFERENCIA:**
{reference_text}

**DOCUMENTOS EN LA BASE:**
{json.dumps([{'id': i, 'content': doc} for i, doc in enumerate(self.documents)], ensure_ascii=False, indent=2)}

**TAREA:**
Encuentra los {max_results} documentos más similares semánticamente al texto de referencia.

**FORMATO DE RESPUESTA:**
Responde SOLO con IDs separados por comas, ordenados por similitud (más similar primero).
Ejemplo: 1,3,0
Si ninguno es similar, responde: ninguno"""

        try:
            result = ollama_run_for_kb("llama-3.3-70b-versatile", prompt)
            
            if result.strip().lower() == "ninguno":
                return []
            
            # Parsear y retornar documentos similares
            doc_ids = []
            for id_str in result.strip().split(','):
                try:
                    doc_id = int(id_str.strip())
                    if 0 <= doc_id < len(self.documents):
                        doc_ids.append(doc_id)
                except ValueError:
                    continue
            
            similar_docs = []
            for doc_id in doc_ids:
                similar_docs.append({
                    'index': doc_id,
                    'document': self.documents[doc_id],
                    'preview': self.documents[doc_id][:200] + "..." if len(self.documents[doc_id]) > 200 else self.documents[doc_id],
                    'similarity_rank': len(similar_docs) + 1
                })
            
            logger.info(f"🔗 Encontrados {len(similar_docs)} documentos similares")
            return similar_docs
            
        except Exception as e:
            logger.error(f"❌ Error buscando documentos similares: {e}")
            return []

    def __str__(self):
        """Representación string de la base de conocimientos"""
        return f"KnowledgeBase(namespace='{self.namespace}', docs={len(self.documents)})"

    def __len__(self):
        """Permite usar len() en la instancia"""
        return len(self.documents)

# Función de utilidad para testing
def test_knowledge_base():
    """Prueba las funcionalidades de la base de conocimientos"""
    print("🧪 Probando KnowledgeBase con Groq...")
    
    # Crear instancia de prueba
    kb = KnowledgeBase(namespace="test")
    
    # Limpiar para prueba fresca
    kb.clear_all_documents()
    
    # Agregar documentos de prueba
    test_docs = [
        "La fotosíntesis es el proceso por el cual las plantas convierten la luz solar en energía química mediante clorofila.",
        "Python es un lenguaje de programación interpretado de alto nivel, conocido por su sintaxis clara y legible.",
        "La inteligencia artificial incluye machine learning, deep learning y procesamiento de lenguaje natural.",
        "El cambio climático se refiere al calentamiento global causado por las emisiones de gases de efecto invernadero.",
        "Los algoritmos de machine learning pueden ser supervisados, no supervisados o de aprendizaje por refuerzo."
    ]
    
    for doc in test_docs:
        kb.add_document(doc)
    
    print(f"✅ Agregados {kb.get_document_count()} documentos")
    
    # Probar recuperación de documentos relevantes
    query = "¿Cómo funciona la fotosíntesis en las plantas?"
    print(f"\n🔍 Consultando: '{query}'")
    
    result = kb.retrieve_relevant_documents(query, max_docs=2)
    print(f"📄 Resultado: {result[:200]}...")
    
    # Probar búsqueda semántica
    print(f"\n🧠 Búsqueda semántica para: '{query}'")
    semantic_results = kb.semantic_search(query, max_results=2)
    for i, doc in enumerate(semantic_results):
        print(f"   {i+1}. [Rank {doc.get('relevance_rank', '?')}] {doc['preview']}")
    
    # Probar búsqueda de similitud
    reference_text = "Los algoritmos de aprendizaje automático"
    print(f"\n🔗 Documentos similares a: '{reference_text}'")
    similar_docs = kb.find_similar_documents(reference_text, max_results=2)
    for doc in similar_docs:
        print(f"   - {doc['preview']}")
    
    # Mostrar estadísticas
    stats = kb.get_knowledge_stats()
    print(f"\n📊 Estadísticas finales:")
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    print("\n✅ Test completado exitosamente!")
    return True

if __name__ == "__main__":
    # Configurar logging para testing
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    test_knowledge_base()
