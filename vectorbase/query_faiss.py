import faiss
import numpy as np
import os

def load_faiss_index(index_path: str):
    if not os.path.exists(index_path):
        raise FileNotFoundError(f"Index file not found: {index_path}")
    try:
        index = faiss.read_index(index_path)
        return index
    except Exception as e:
        print(f"Error loading FAISS index: {e}")
        raise

def search_faiss_index(index: faiss.Index, query_vector: np.ndarray, k: int = 5):
    if query_vector.ndim == 1:
        query_vector = np.expand_dims(query_vector, axis=0)

    if query_vector.shape[1] != index.d:
        raise ValueError(f"Query vector dimension ({query_vector.shape[1]}) does not match index dimension ({index.d}).")

    try:
        distances, indices = index.search(query_vector.astype('float32'), k)
        return distances, indices
    except Exception as e:
        print(f"Error searching FAISS index: {e}")
        raise

if __name__ == '__main__':

    INDEX_FILE_PATH = "faiss_index.bin"

    DIMENSION = 768

    print(f"Attempting to load FAISS index from '{INDEX_FILE_PATH}'...")


    if not os.path.exists(INDEX_FILE_PATH):
        print(f"Warning: Index file '{INDEX_FILE_PATH}' not found.")
        print("Creating a dummy index for demonstration. Please ensure you have generated the actual index using build_index.py.")

        dummy_index = faiss.IndexFlatL2(DIMENSION)
        dummy_data = np.random.rand(100, DIMENSION).astype('float32')
        dummy_index.add(dummy_data)
        faiss.write_index(dummy_index, INDEX_FILE_PATH)
        print(f"Created and saved dummy index to '{INDEX_FILE_PATH}'.")

    try:
        faiss_index = load_faiss_index(INDEX_FILE_PATH)
        print(f"FAISS index successfully loaded. Total vectors in index: {faiss_index.ntotal}, dimension: {faiss_index.d}")


        if faiss_index.d > 0:
            example_query_vector = np.random.rand(1, faiss_index.d).astype('float32')
            print(f"\nSearching with example query vector (top 5 similar results):")
            print(f"Query vector (first 10 elements): {example_query_vector[0, :10]}...")

            k_neighbors = 5
            distances, indices = search_faiss_index(faiss_index, example_query_vector, k=k_neighbors)

            print(f"\nQuery results:")
            print(f"  Indices of {k_neighbors} most similar vectors: {indices}")
            print(f"  Corresponding distances: {distances}")

            if faiss_index.ntotal == 0:
                print("\nNote: Index is currently empty. Search results may not be meaningful.")
            elif k_neighbors > faiss_index.ntotal:
                print(f"\nNote: Requested number of neighbors ({k_neighbors}) is greater than total vectors in index ({faiss_index.ntotal}).")

        else:
            print("\nError: Index dimension is 0, cannot execute query. Please check the index file.")

    except FileNotFoundError as fnf_error:
        print(f"Error: {fnf_error}")
        print("Please ensure you have run build_index.py to create the FAISS index file (default: 'faiss_index.bin'),")
        print("or update INDEX_FILE_PATH to the correct path.")
    except ValueError as val_error:
        print(f"Value error: {val_error}")
    except Exception as e:
        print(f"Unexpected error occurred: {e}")

