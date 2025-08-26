# == file: knowledge_base.py ==
"""
Trimmed and hardened version of the original KnowledgeBase.
Changes made:
- Added file locking (filelock) when saving index.json to avoid corruption.
- Basic sanitization when building prompts.
- Defensive checks for responses from ollama/groq bridge.
- Reduced public surface to the essentials used by routes.py: add_document, load_documents, save_documents, retrieve_relevant_documents.
"""

import json
import os
import re
from typing import List, Dict, Optional

try:
    from filelock import FileLock
except Exception:
    FileLock = None

# Location where vector stores live (same idea as original)
BASE_DIR = os.path.join(os.path.dirname(__file__), "vector_store")
os.makedirs(BASE_DIR, exist_ok=True)


def _sanitize_for_prompt(text: str, max_len: int = 4000) -> str:
    # Remove control chars and very long whitespace sequences, limit length
    text = re.sub(r"[\x00-\x08\x0b-\x1f]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_len:
        return text[:max_len] + "..."
    return text


class KnowledgeBase:
    def __init__(self, namespace: str = "default"):
        self.namespace = namespace
        self.index_file = os.path.join(BASE_DIR, namespace, "index.json")
        os.makedirs(os.path.dirname(self.index_file), exist_ok=True)
        self.documents: List[Dict] = []
        self._load_documents()

    def _load_documents(self):
        if not os.path.exists(self.index_file):
            self.documents = []
            return
        try:
            with open(self.index_file, "r", encoding="utf-8") as f:
                self.documents = json.load(f)
        except Exception:
            # If the file is corrupted, rename it and start fresh
            bad = self.index_file + ".corrupt"
            try:
                os.rename(self.index_file, bad)
            except Exception:
                pass
            self.documents = []

    def save_documents(self):
        if FileLock is None:
            # best-effort fallback: atomic write
            tmp = self.index_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.documents, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.index_file)
            return

        lock_path = self.index_file + ".lock"
        lock = FileLock(lock_path, timeout=5)
        with lock:
            tmp = self.index_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.documents, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.index_file)

    def add_document(self, doc_id: str, content: str, meta: Optional[dict] = None):
        doc = {"id": doc_id, "text": content, "meta": meta or {}}
        self.documents.append(doc)
        self.save_documents()

    def retrieve_relevant_documents(self, query: str, top_k: int = 5) -> List[Dict]:
        """
        Very small wrapper that prepares a sanitized prompt and calls an external
        semantic search function. This function is defensive: if the bridge fails,
        it falls back to a cheap keyword-based rank.
        """
        from app.ollama_stream import ollama_run_for_kb

        query_s = _sanitize_for_prompt(query, max_len=1000)

        try:
            result = ollama_run_for_kb(query_s, namespace=self.namespace, top_k=top_k)
            # Expecting a list of dicts or a text summary; be permissive
            if isinstance(result, list):
                return result[:top_k]
            if isinstance(result, str) and result.strip():
                return [{"id": "llm_summary", "text": result.strip(), "meta": {}}]
        except Exception:
            # fallthrough to cheap local rank
            pass

        # cheap fallback: simple substring match
        ranked = []
        qlow = query_s.lower()
        for d in self.documents:
            score = d.get("text", "").lower().count(qlow)
            if score > 0:
                ranked.append((score, d))
        ranked.sort(key=lambda x: x[0], reverse=True)
        return [d for _, d in ranked][:top_k]