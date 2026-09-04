import faiss
import numpy as np
import os


def build_and_save_faiss_index(data, index_path="vectorbase/faiss.index"):
    if data is None or data.shape[0] == 0:
        print("Error: Input data is empty, cannot build index.")
        return

    dimension = data.shape[1]

    index = faiss.IndexFlatL2(dimension)

    print(f"Building index with {data.shape[0]} vectors of dimension {dimension}...")

    index.add(data)

    print(f"Index build complete, containing {index.ntotal} vectors.")

    index_dir = os.path.dirname(index_path)
    if index_dir and not os.path.exists(index_dir):
        os.makedirs(index_dir)
        print(f"Created directory: {index_dir}")

    faiss.write_index(index, index_path)
    print(f"FAISS index successfully saved to: {index_path}")


def generate_sample_data(num_vectors=1000, dimension=128):
    print(f"Generating {num_vectors} sample vectors of dimension {dimension}...")

    data = np.random.rand(num_vectors, dimension).astype('float32')
    return data


if __name__ == "__main__":

    sample_vectors = generate_sample_data(num_vectors=5000, dimension=768)

    output_index_path = "vectorbase/my_faiss_index.index"

    build_and_save_faiss_index(sample_vectors, output_index_path)

    if os.path.exists(output_index_path):
        try:
            print(f"\nAttempting to load saved index from {output_index_path}...")
            loaded_index = faiss.read_index(output_index_path)
            print(f"Index loaded successfully, containing {loaded_index.ntotal} vectors.")

        except Exception as e:
            print(f"Error loading or querying index: {e}")
    else:
        print(f"Error: Index file {output_index_path} not found.")
