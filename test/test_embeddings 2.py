from llm_query import embed_text, init_vectorizer

print("Testing embedding system...")

texts = [
    "CVE-2024-1234: Buffer overflow in Apache web server",
    "CVE-2024-5678: SQL injection vulnerability in MySQL",
    "CVE-2024-9999: Remote code execution in nginx"
]

print("\n1. Initializing vectorizer with sample texts...")
init_vectorizer(texts)

print("\n2. Testing embeddings...")
for text in texts:
    emb = embed_text(text)
    print(f"   {text[:50]}... -> embedding length: {len(emb)}")

print("\n3. Testing query embedding...")
query = "What vulnerabilities affect Apache?"
query_emb = embed_text(query)
print(f"   Query: {query}")
print(f"   Embedding length: {len(query_emb)}")

print("\nSuccess! Embedding system works.")

