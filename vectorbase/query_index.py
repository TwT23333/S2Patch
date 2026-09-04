import os
import json
import faiss
import numpy as np
from models.embedding_helper import CodeEmbedder


class VectorDatabaseQuerier:
    def __init__(self, indices_dir="vectorbase/indices", model_type="bge-code-v1"):
        self.indices_dir = indices_dir
        self.embedder = CodeEmbedder(model_type=model_type)
        self.indices = {}
        self.metadata = {}

        self.load_all_indices()

    def load_all_indices(self):
        if not os.path.exists(self.indices_dir):
            print(f"Index directory {self.indices_dir} does not exist. Please build the index first.")
            return

        index_files = [f for f in os.listdir(self.indices_dir) if f.endswith('.index')]

        if not index_files:
            print(f"No index files found in index directory {self.indices_dir}.")
            return

        for index_file in index_files:
            cwe_type = index_file.replace('.index', '')
            metadata_file = f"{cwe_type}_metadata.json"

            index_path = os.path.join(self.indices_dir, index_file)
            metadata_path = os.path.join(self.indices_dir, metadata_file)

            try:
                self.indices[cwe_type] = faiss.read_index(index_path)

            except Exception as e:
                print(f"Error loading index {index_path}: {e}")
                continue

            try:
                if os.path.exists(metadata_path):
                    with open(metadata_path, 'r', encoding='utf-8') as f:
                        self.metadata[cwe_type] = json.load(f)
                else:
                    print(f"Metadata file {metadata_path} does not exist")
                    self.metadata[cwe_type] = []
            except Exception as e:
                print(f"Error loading metadata {metadata_path}: {e}")
                self.metadata[cwe_type] = []

    def vectorize_text(self, text):
        embeddings_array = self.embedder.get_embeddings([text])
        if embeddings_array is not None and embeddings_array.shape[0] > 0:
            return embeddings_array[0]
        else:
            print(f"Warning: Text '{text[:50]}...' vectorization failed or returned empty. Returning zero vector.")
            return np.zeros(self.embedder.dim if hasattr(self.embedder, 'dim') else 3072)

    def search(self, query_text, top_k=5, cwe_type=None):
        if not self.indices:
            print("No indices loaded, cannot perform search.")
            return []

        query_vector = self.vectorize_text(query_text).reshape(1, -1).astype('float32')

        results = []

        cwe_types_to_search = [cwe_type] if cwe_type and cwe_type in self.indices else self.indices.keys()

        for cwe in cwe_types_to_search:
            if cwe not in self.indices or cwe not in self.metadata:
                continue

            index = self.indices[cwe]
            metadata_list = self.metadata[cwe]

            if top_k > index.ntotal:
                k = index.ntotal
            else:
                k = top_k

            if k == 0:
                continue

            distances, indices = index.search(query_vector, k)

            for i, idx in enumerate(indices[0]):
                if idx < len(metadata_list):
                    result = {
                        "distance": float(distances[0][i]),
                        "cwe_type": cwe,
                        "metadata": metadata_list[idx]
                    }
                    results.append(result)

        results.sort(key=lambda x: x["distance"])

        return results[:top_k]


if __name__ == "__main__":

    querier = VectorDatabaseQuerier()

    query_text = "Vulnerability caused by null pointer dereference, needs to add null pointer check to fix"
    results = querier.search(query_text, top_k=3)

    print(f"Query: '{query_text}'")
    print("Search results:")

    for i, result in enumerate(results):
        print(f"\nResult #{i+1} (distance: {result['distance']:.4f}, CWE type: {result['metadata']['cwe_type']}, top-level parent: {result['cwe_type']})")
        print(f"CVE: {result['metadata']['cve_id']}")
        print(f"Vulnerability state: {result['metadata']['final_llm1_pre_repair_state'][:150]}...")
        print(f"Repair strategy: {result['metadata']['final_llm1_abstract_strategy'][:150]}...")
