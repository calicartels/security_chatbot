import faiss
import numpy as np
import pickle
import os

class VectorDB:
    def __init__(self, embed_func):
        self.embed_func = embed_func
        self.index = None
        self.cves = []
        self.dimension = 768
        
    def build_index(self, cves):
        if not cves:
            return False
            
        self.cves = cves
        
        texts = [f"{cve['id']}: {cve['description']}" for cve in cves]
        
        embeddings = []
        for text in texts:
            emb = self.embed_func(text)
            embeddings.append(emb)
        
        embeddings_array = np.array(embeddings).astype('float32')
        self.dimension = embeddings_array.shape[1]
        
        self.index = faiss.IndexFlatL2(self.dimension)
        self.index.add(embeddings_array)
        
        return True
    
    def search_relevant(self, query, k=5):
        if self.index is None or self.index.ntotal == 0:
            return []
        
        query_emb = self.embed_func(query)
        query_array = np.array([query_emb]).astype('float32')
        
        k = min(k, self.index.ntotal)
        distances, indices = self.index.search(query_array, k)
        
        results = []
        for i, idx in enumerate(indices[0]):
            if idx < len(self.cves):
                results.append({
                    **self.cves[idx],
                    "score": float(distances[0][i])
                })
        
        return results
    
    def save_index(self, index_path="faiss_index", cves_path="cves.pkl"):
        if self.index is None:
            return False
        
        faiss.write_index(self.index, index_path)
        
        with open(cves_path, "wb") as f:
            pickle.dump(self.cves, f)
        
        return True
    
    def load_index(self, index_path="faiss_index", cves_path="cves.pkl"):
        if not os.path.exists(index_path) or not os.path.exists(cves_path):
            return False
        
        self.index = faiss.read_index(index_path)
        
        with open(cves_path, "rb") as f:
            self.cves = pickle.load(f)
        
        return True

