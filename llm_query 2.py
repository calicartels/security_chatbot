import os
from dotenv import load_dotenv
import warnings
import requests
import json

warnings.filterwarnings('ignore')

load_dotenv()

embedding_model = None

def init_vectorizer(texts):
    pass

def embed_text(text):
    global embedding_model
    
    if embedding_model is None:
        print("Loading sentence transformer model...")
        from sentence_transformers import SentenceTransformer
        embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
    
    embedding = embedding_model.encode(text, convert_to_numpy=True, show_progress_bar=False)
    return embedding.tolist()

def query_gemini(prompt):
    api_key = os.getenv("GEMINI_API_KEY")
    
    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent"
    
    headers = {
        "x-goog-api-key": api_key,
        "Content-Type": "application/json"
    }
    
    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }]
    }
    
    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()
    
    result = response.json()
    return result["candidates"][0]["content"]["parts"][0]["text"]

def build_rag_prompt(user_query, infrastructure, relevant_cves):
    cve_context = ""
    
    if relevant_cves:
        cve_context = "\n\nRelevant CVEs from database:\n"
        for i, cve in enumerate(relevant_cves[:5], 1):
            description = (cve.get('description') or '')
            cve_context += f"\n{i}. {cve.get('id', 'Unknown')}\n"
            if description:
                cve_context += f"   Description: {description[:300]}\n"
            if cve.get('severity'):
                cve_context += f"   Severity: {cve['severity']}\n"
            if cve.get('matched_components'):
                cve_context += f"   Matches: {', '.join(cve['matched_components'])}\n"
            if cve.get('affected_products'):
                products = cve['affected_products'][:3]
                cve_context += f"   Affected: {', '.join(products)}\n"
    else:
        cve_context = "\n\nNo retrieved CVEs were confidently matched to the provided infrastructure. Offer guidance on monitoring, patching cadence, and next investigative steps.\n"
    
    infrastructure_context = ""
    if infrastructure:
        infrastructure_context = f"\n\nUser's Infrastructure:\n{infrastructure}\n"
    
    prompt = f"""You are a cybersecurity assistant. Answer the user's security question based on the provided context.

{infrastructure_context}
{cve_context}

User Question: {user_query}

Provide a clear, actionable response. If the infrastructure is affected by any CVEs, explain which ones and recommend mitigation steps. Be specific and technical."""
    
    return prompt

def chat_response(user_query, infrastructure, relevant_cves):
    prompt = build_rag_prompt(user_query, infrastructure, relevant_cves)
    return query_gemini(prompt)

