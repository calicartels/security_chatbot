# Security CVE Chatbot

A RAG-based security chatbot that fetches CVE data from NVD and OSV.dev, stores it in a vector database, and answers security questions using Google Gemini.

## Features

- Fetch CVEs from NVD or OSV.dev (last year of data)
- Vector search using FAISS and Gemini embeddings
- Context-aware responses using RAG
- Infrastructure-specific vulnerability analysis
- Clean Streamlit interface

## Setup

1. Activate the virtual environment and install dependencies:
```bash
source chatbot_env/bin/activate
pip install -r requirements.txt
```

2. Create a `.env` file with your Gemini API key:
```bash
echo "GEMINI_API_KEY=YOUR_API_KEY_HERE" > .env
```

Get your API key from: https://aistudio.google.com/app/apikey

3. Run the app:
```bash
source chatbot_env/bin/activate
streamlit run app.py
```

## Usage

1. Select data source (NVD or OSV.dev) in the sidebar
2. Click "Fetch CVEs" to load vulnerability data
3. Enter your infrastructure details in the text area
4. Ask security questions in the chat interface

## Example Queries

- "What vulnerabilities affect nginx 1.18?"
- "Show me critical CVEs from the last month"
- "Which vulnerabilities in my infrastructure should I prioritize?"
- "Explain CVE-2024-XXXXX and its impact"

## Architecture

- `app.py` - Streamlit interface
- `cve_fetch.py` - CVE data fetchers
- `vector_db.py` - FAISS vector store
- `llm_query.py` - Gemini integration

### Simplified Flow

```
User ➜ Streamlit UI (`app.py`) ➜
    Fetch CVEs (`cve_fetch.py`) ➜ Normalize & store
    Build/Search FAISS index (`vector_db.py`) ➜
    Filter + Rerank (`cve_processing.py`) ➜
    RAG prompt + Gemini response (`llm_query.py`)
```

## Notes

- NVD fetches in 30-day chunks with 6-second delays between chunks (rate limits)
- Larger date ranges take longer (e.g., 150 days = 5 chunks = ~30 seconds)
- OSV.dev is faster but may have different CVE coverage
- Watch terminal for fetch progress and any errors

## Troubleshooting

If you get "Failed to fetch CVEs":

1. Test the API connection:
```bash
python test_fetch.py
```

2. Check terminal for error messages - they'll show:
   - HTTP status codes
   - API response errors
   - Network issues

3. Common fixes:
   - Start with fewer days (30-60) instead of 365
   - Check internet connection
   - Verify NVD API is accessible: https://nvd.nist.gov/developers/api
   - Try the other data source (NVD vs OSV.dev)

4. If NVD fails due to rate limits or connectivity, OSV.dev uses NVD as fallback with recent CVEs

## Architecture Diagram

```
┌──────────────────────┐
│  CVE Data Sources    │
│  - NVD API           │
│  - OSV.dev           │
└─────────┬────────────┘
          │
Ingestion & Normalization
          │ (cve_fetch.py)
          ▼
Embeddings + Index Build
(Gemini embeddings + FAISS via vector_db.py)
          │
          ▼
Vector Store (FAISS index + metadata)
          │                 ┌───────────────┐
Retrieval (top-k)           │User Query     │
+ Cross-encoder rerank      │Infrastructure │
(vector_db + cve_processing)└──────┬────────┘
          │                        │
          └──────────────┬─────────┘
                         ▼
              Prompt Assembly
             (llm_query.py builds
               context prompt)
                         │
                         ▼
               LLM Generation
                (Google Gemini)
                         │
                         ▼
                Streamlit Chat UI
                    (app.py)
```



## References:
- Built interactively with Cursor IDE (https://cursor.sh)
- National Vulnerability Database (NVD): https://nvd.nist.gov
- CISA Known Exploited Vulnerabilities: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Google Gemini API quickstart: https://ai.google.dev/gemini-api/docs
- RAG design patterns (Pinecone): https://www.pinecone.io/learn/retrieval-augmented-generation/
- RAG best practices (LangChain): https://python.langchain.com/docs/modules/chains/foundational/rag
