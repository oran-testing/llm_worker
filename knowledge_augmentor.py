import json
import logging
from typing import Dict, Any, Optional

import chromadb
from chromadb.utils import embedding_functions

class KnowledgeAugmentor:
    """
    Minimal retrieval helper around ChromaDB to fetch domain snippets
    and build a context string for prompt augmentation.

    NOTE: To keep context relevant, chunks should be upserted with metadata:
      metadatas=[{"source": "kb/sniffer.md", "component": "sniffer"}, ...]
    """
    def __init__(self, db_dir="vector_db", collection_name="rf_knowledge", model_name="all-MiniLM-L6-v2"):
        logging.info("Initializing KnowledgeAugmentor...")
        self.collection = None
        try:
            sentence_transformer_ef = embedding_functions.SentenceTransformerEmbeddingFunction(model_name=model_name)
            db_client = chromadb.PersistentClient(path=db_dir)
            self.collection = db_client.get_or_create_collection(
                name=collection_name, embedding_function=sentence_transformer_ef
            )
        except Exception as e:
            logging.warning(f"KnowledgeAugmentor initialization failed (will proceed without RAG): {e}")
        logging.info("KnowledgeAugmentor initialized.")

    # component-filtered retrieval to avoid mixing unrelated docs
    def retrieve_context_for_component(self, component: str, query: str, n_results: int = 3) -> str:
        if self.collection is None:
            logging.warning("[KnowledgeAugmentor] No collection available (init failed), skipping retrieval.")
            return ""
        logging.info(f"[KnowledgeAugmentor] Retrieving context for component='{component}' | query='{query}'")
        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=n_results,
                where={"component": component}
            )
        except Exception as e:
            logging.warning(f"[KnowledgeAugmentor] Query failed: {e}")
            return ""
        docs = results.get('documents', [[]])[0] if results else []
        if not docs:
            return ""
        ctx = []
        for i, doc in enumerate(docs):
            try:
                source = results['metadatas'][0][i].get('source', 'unknown')
            except Exception:
                source = "unknown"
            logging.info(f"  [Doc {i+1} from '{source}']: {doc[:120].strip().replace(chr(10),' ')}...")
            ctx.append(f"- From {source}:\n{doc}")
        return "\n\n".join(ctx).strip()

    @staticmethod
    def build_augmented_prompt(context: str, system_prompt_block: str, user_request: str,
                               planner_params: Optional[Dict[str, Any]] = None) -> str:
        """
        Structured prompt used consistently across components.
        - Context: retrieved engineering rules/examples
        - Instructions: the schema/formatting portion of the system prompt
        - User Request: the actual user input/goal
        - Planner Parameters: authoritative constraints from the planner when present
        """
        params_block = ""
        if planner_params:
            params_block = f"\n--- PLANNER PARAMETERS (Authoritative) ---\n{json.dumps(planner_params, indent=2)}\n--- END OF PLANNER PARAMETERS ---\n"
        return f"""You are an expert RF systems assistant.
First, review the provided CONTEXT for critical engineering rules.
Then, use that context to follow the INSTRUCTIONS to generate a valid JSON configuration that fulfills the USER REQUEST.
If PLANNER PARAMETERS are provided, you MUST honor them (they override defaults and inferred values).

--- CONTEXT (Rules & Formulas) ---
{context}
--- END OF CONTEXT ---

--- INSTRUCTIONS (Schema & Formatting) ---
{system_prompt_block}
--- END OF INSTRUCTIONS ---

--- USER REQUEST ---
{user_request}
{params_block}Provide only the final JSON object.

--- JSON OUTPUT ---""".strip()

