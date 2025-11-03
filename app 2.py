import streamlit as st
from cve_fetch import fetch_nvd, fetch_osv, normalize_cves
from vector_db import VectorDB
from llm_query import embed_text, chat_response
from cve_processing import filter_and_rank_cves

st.set_page_config(page_title="Security CVE Chatbot", layout="wide")

if "vector_db" not in st.session_state:
    st.session_state.vector_db = VectorDB(embed_text)

if "messages" not in st.session_state:
    st.session_state.messages = []

if "cves_loaded" not in st.session_state:
    st.session_state.cves_loaded = False

if "data_source" not in st.session_state:
    st.session_state.data_source = "NVD"

if "infrastructure_input" not in st.session_state:
    st.session_state.infrastructure_input = ""

st.title("Security CVE Chatbot")

with st.sidebar:
    st.header("Configuration")
    
    st.subheader("Data Source")
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("NVD", use_container_width=True):
            st.session_state.data_source = "NVD"
    
    with col2:
        if st.button("OSV.dev", use_container_width=True):
            st.session_state.data_source = "OSV.dev"
    
    st.write(f"Selected: **{st.session_state.data_source}**")
    
    days = st.slider("Days to fetch", 30, 730, 365)
    
    if st.button("Fetch CVEs", use_container_width=True):
        with st.spinner(f"Fetching CVEs from {st.session_state.data_source}... (check terminal for progress)"):
            try:
                if st.session_state.data_source == "NVD":
                    cves = fetch_nvd(days)
                else:
                    cves = fetch_osv(days)
                
                cves = normalize_cves(cves)
                
                if cves:
                    with st.spinner("Building vector index..."):
                        st.session_state.vector_db.build_index(cves)
                    st.session_state.cves_loaded = True
                    st.success(f"✓ Loaded {len(cves)} CVEs from {st.session_state.data_source}")
                else:
                    st.error(f"No CVEs returned from {st.session_state.data_source}. Check terminal for error details.")
            except Exception as e:
                st.error(f"Error: {str(e)}")
    
    st.divider()
    
    st.subheader("Infrastructure")
    infrastructure = st.text_area(
        "Describe your infrastructure",
        placeholder="e.g., Ubuntu 22.04, nginx 1.18.0, Python 3.10, PostgreSQL 14",
        height=150,
        key="infrastructure_input"
    )
    
    if st.button("Clear Chat", use_container_width=True):
        st.session_state.messages = []
        st.rerun()

st.divider()

for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])
        if "cves" in message and message["cves"]:
            with st.expander("Retrieved CVEs"):
                for cve in message["cves"]:
                    st.write(f"**{cve['id']}** - {cve['severity']}")
                    st.caption(cve['description'][:200] + "...")

if prompt := st.chat_input("Ask a security question..."):
    if not st.session_state.cves_loaded:
        st.warning("Please fetch CVEs first using the sidebar")
    else:
        st.session_state.messages.append({"role": "user", "content": prompt})
        
        with st.chat_message("user"):
            st.markdown(prompt)
        
        with st.chat_message("assistant"):
            with st.spinner("Searching and analyzing..."):
                raw_cves = st.session_state.vector_db.search_relevant(prompt, k=15)
                relevant_cves = filter_and_rank_cves(prompt, infrastructure, raw_cves, max_results=5)

                if not relevant_cves and infrastructure.strip():
                    st.info("No vulnerabilities matching your infrastructure were found in the retrieved CVEs.")

                response = chat_response(prompt, infrastructure, relevant_cves)

                st.markdown(response)
                
                if relevant_cves:
                    with st.expander("Retrieved CVEs"):
                        for cve in relevant_cves:
                            st.write(f"**{cve['id']}** - {cve['severity']}")
                            if cve.get("matched_components"):
                                st.caption("Matches: " + ", ".join(cve["matched_components"]))
                            st.caption(cve['description'][:200] + "...")
        
        st.session_state.messages.append({
            "role": "assistant",
            "content": response,
            "cves": relevant_cves
        })

