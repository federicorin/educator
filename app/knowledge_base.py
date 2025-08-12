import os
import json
from .ollama_stream import ollama_run_for_kb  # 🔥 CAMBIO: usar función del archivo actualizado

class KnowledgeBase:
    def __init__(self, namespace="global"):
        self.namespace = namespace
        self.db_folder = os.path.join("vector_store", self.namespace)
        os.makedirs(self.db_folder, exist_ok=True)
        self.index_file = os.path.join(self.db_folder, "index.json")
        self.documents = []
        self.load_documents()

    def load_documents(self):
        if os.path.exists(self.index_file):
            with open(self.index_file, "r", encoding="utf-8") as f:
                self.documents = json.load(f)
        else:
            self.documents = []

    def save_documents(self):
        with open(self.index_file, "w", encoding="utf-8") as f:
            json.dump(self.documents, f, ensure_ascii=False, indent=2)

    def add_document(self, text):
        self.documents.append(text)
        self.save_documents()

    def retrieve_relevant_documents(self, query, max_docs=3):
        prompt = f"""
        Dado el siguiente contexto:
        {json.dumps(self.documents, ensure_ascii=False, indent=2)}

        Y esta pregunta:
        {query}

        Devuelve un resumen de los documentos más relevantes (máximo {max_docs}) como texto, para ayudar a responder la pregunta.
        """
        try:
            # 🔥 CAMBIO: usar función interna en lugar de subprocess
            result = ollama_run_for_kb("deepseek-r1:14b_educator_", prompt)
            return result.strip()
        except Exception as e:
            return f"⚠️ Error al buscar contexto relevante: {e}"
