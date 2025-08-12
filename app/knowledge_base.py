# knowledge_base.py - ADAPTADO PARA GROQ

import os
import json
from .ollama_stream import ollama_run_for_kb  # ✅ Ahora usa Groq internamente

class KnowledgeBase:
    def __init__(self, namespace="global"):
        self.namespace = namespace
        self.db_folder = os.path.join("vector_store", self.namespace)
        os.makedirs(self.db_folder, exist_ok=True)
        self.index_file = os.path.join(self.db_folder, "index.json")
        self.documents = []
        self.load_documents()

    def load_documents(self):
        """Carga los documentos desde el archivo de índice"""
        if os.path.exists(self.index_file):
            with open(self.index_file, "r", encoding="utf-8") as f:
                self.documents = json.load(f)
        else:
            self.documents = []

    def save_documents(self):
        """Guarda los documentos en el archivo de índice"""
        with open(self.index_file, "w", encoding="utf-8") as f:
            json.dump(self.documents, f, ensure_ascii=False, indent=2)

    def add_document(self, text):
        """Agrega un nuevo documento a la base de conocimientos"""
        if text and text.strip():  # Validación básica
            self.documents.append(text.strip())
            self.save_documents()
            return True
        return False

    def remove_document(self, index):
        """Remueve un documento por índice"""
        if 0 <= index < len(self.documents):
            removed = self.documents.pop(index)
            self.save_documents()
            return removed
        return None

    def get_document_count(self):
        """Retorna el número total de documentos"""
        return len(self.documents)

    def retrieve_relevant_documents(self, query, max_docs=3):
        """
        Usa Groq Cloud (Llama 3.3 70B) para encontrar documentos relevantes
        """
        if not self.documents:
            return "No hay documentos en la base de conocimientos."
        
        if not query.strip():
            return "Consulta vacía."

        # 🎯 PROMPT OPTIMIZADO PARA LLAMA 3.3 70B
        prompt = f"""Eres un sistema de recuperación de información inteligente. Tu tarea es analizar una base de conocimientos y encontrar la información más relevante para responder una pregunta específica.

**BASE DE CONOCIMIENTOS:**
{json.dumps(self.documents, ensure_ascii=False, indent=2)}

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
            # ✅ Esta función ahora usa Groq Cloud internamente
            result = ollama_run_for_kb("llama-3.3-70b-versatile", prompt)  # Modelo actualizado
            return result.strip() if result else "No se pudo procesar la consulta."
            
        except Exception as e:
            return f"⚠️ Error al buscar contexto relevante: {e}"

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
        
        return matching_docs

    def get_all_documents(self):
        """Retorna todos los documentos con sus índices"""
        return [{'index': i, 'document': doc} for i, doc in enumerate(self.documents)]

    def update_document(self, index, new_text):
        """Actualiza un documento existente"""
        if 0 <= index < len(self.documents) and new_text.strip():
            self.documents[index] = new_text.strip()
            self.save_documents()
            return True
        return False

    def clear_all_documents(self):
        """Elimina todos los documentos"""
        self.documents = []
        self.save_documents()

    def export_knowledge_base(self, filepath):
        """Exporta la base de conocimientos a un archivo JSON"""
        try:
            export_data = {
                'namespace': self.namespace,
                'document_count': len(self.documents),
                'documents': self.documents,
                'exported_at': json.dumps(str(os.path.getctime(self.index_file)) if os.path.exists(self.index_file) else "unknown")
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"Error exportando: {e}")
            return False

    def import_knowledge_base(self, filepath):
        """Importa una base de conocimientos desde un archivo JSON"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                import_data = json.load(f)
            
            if 'documents' in import_data:
                # Agregar documentos importados a los existentes
                imported_docs = import_data['documents']
                for doc in imported_docs:
                    if doc.strip() and doc not in self.documents:  # Evitar duplicados
                        self.documents.append(doc.strip())
                
                self.save_documents()
                return len(imported_docs)
            return 0
        except Exception as e:
            print(f"Error importando: {e}")
            return 0

    def get_knowledge_stats(self):
        """Retorna estadísticas de la base de conocimientos"""
        if not self.documents:
            return {
                'total_documents': 0,
                'total_characters': 0,
                'total_words': 0,
                'average_document_length': 0
            }
        
        total_chars = sum(len(doc) for doc in self.documents)
        total_words = sum(len(doc.split()) for doc in self.documents)
        
        return {
            'total_documents': len(self.documents),
            'total_characters': total_chars,
            'total_words': total_words,
            'average_document_length': total_chars // len(self.documents),
            'namespace': self.namespace
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
            result = ollama_run_for_kb("llama-3.3-70b-versatile", prompt)
            
            if result.strip().lower() == "ninguno":
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
                    'preview': self.documents[doc_id][:200] + "..." if len(self.documents[doc_id]) > 200 else self.documents[doc_id]
                })
            
            return relevant_docs
            
        except Exception as e:
            print(f"Error en búsqueda semántica: {e}")
            # Fallback a búsqueda simple
            return self.search_documents(query)[:max_results]

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
        "La fotosíntesis es el proceso por el cual las plantas convierten la luz solar en energía química.",
        "Python es un lenguaje de programación interpretado de alto nivel.",
        "La inteligencia artificial incluye machine learning, deep learning y procesamiento de lenguaje natural.",
        "El cambio climático se refiere al calentamiento global causado por las emisiones de gases de efecto invernadero."
    ]
    
    for doc in test_docs:
        kb.add_document(doc)
    
    print(f"✅ Agregados {kb.get_document_count()} documentos")
    
    # Probar recuperación de documentos relevantes
    query = "¿Cómo funciona la fotosíntesis?"
    print(f"\n🔍 Consultando: '{query}'")
    
    result = kb.retrieve_relevant_documents(query, max_docs=2)
    print(f"📄 Resultado: {result[:200]}...")
    
    # Probar búsqueda semántica
    print(f"\n🧠 Búsqueda semántica para: '{query}'")
    semantic_results = kb.semantic_search(query, max_results=2)
    for i, doc in enumerate(semantic_results):
        print(f"   {i+1}. {doc['preview']}")
    
    # Mostrar estadísticas
    stats = kb.get_knowledge_stats()
    print(f"\n📊 Estadísticas: {stats}")
    
    return True

if __name__ == "__main__":
    test_knowledge_base()
