import os
import json
import faiss
import numpy as np
from tqdm import tqdm
from utils.cwe_find import CWEProcessor
from models.embedding_helper import CodeEmbedder


class VectorDatabaseBuilder:
    def __init__(self, output_dir="vectorbase/indices", embedding_model="bge-code-v1"):
        self.output_dir = output_dir
        self.cwe_processor = CWEProcessor()
        self.embedder = CodeEmbedder(model_type=embedding_model)

        self.main_cwe_types = [
            "CWE-189", "CWE-254", "CWE-264", "CWE-284", "CWE-310",
            "CWE-399", "CWE-664", "CWE-682", "CWE-691", "CWE-703", "CWE-707"
        ]

        os.makedirs(self.output_dir, exist_ok=True)

    def load_strategy_analysis_data(self, filepaths):

        if isinstance(filepaths, str):
            filepaths = [filepaths]

        combined_data = []

        for filepath in filepaths:
            if os.path.exists(filepath):
                print(f"Loading data file: {filepath}")
                try:
                    with open(filepath, 'r', encoding='utf-8') as file:
                        data = json.load(file)
                        if isinstance(data, list):
                            combined_data.extend(data)
                        else:
                            combined_data.append(data)
                    print(f"Loaded {len(data) if isinstance(data, list) else 1} records from {filepath}")
                except Exception as e:
                    print(f"Error loading file {filepath}: {e}")
            else:
                print(f"Data file does not exist: {filepath}")

        return combined_data

    def get_top_parent_cwe(self, cwe_id):
        if cwe_id is None or not cwe_id.startswith("CWE-"):
            return "CWE-0"

        try:
            _, top_parent = self.cwe_processor.process_cwe(cwe_id)

            if top_parent not in self.main_cwe_types:
                return "CWE-0"

            return top_parent
        except Exception as e:
            print(f"Error processing CWE ID {cwe_id}: {e}")
            return "CWE-0"

    def process_data(self, data):
        grouped_data = {}

        for item in tqdm(data, desc="Processing data by CWE type"):
            cwe_id = item.get("cwe_type")
            top_parent = self.get_top_parent_cwe(cwe_id)

            if top_parent not in grouped_data:
                grouped_data[top_parent] = []

            grouped_data[top_parent].append(item)

        return grouped_data

    def vectorize_text(self, text):
        if not text or len(text.strip()) == 0:

            return np.zeros(self.embedder.dim)

        vectors = self.embedder.get_embeddings([text])
        return vectors[0]

    def build_indices(self, grouped_data):
        for cwe_type, items in tqdm(grouped_data.items(), desc="Building FAISS indices"):

            if not items:
                continue

            vectors = []
            metadata = []

            for item in items:

                pre_repair_state = item.get("final_llm1_pre_repair_state", "")
                if not pre_repair_state:
                    continue

                vector = self.vectorize_text(pre_repair_state)

                if vector is None or len(vector) == 0:
                    continue

                vectors.append(vector)

                metadata.append({
                    "original_row_index": item.get("original_row_index"),
                    "cwe_type": item.get("cwe_type"),
                    "cve_id": item.get("cve_id"),
                    "top_parent_cwe": cwe_type,
                    "code_before": item.get("code_before"),
                    "code_after_ground_truth": item.get("code_after_ground_truth"),
                    "final_llm1_cwe_specific_strategy": item.get("final_llm1_cwe_specific_strategy"),
                    "final_llm1_pre_repair_state": pre_repair_state,
                    "final_llm1_abstract_strategy": item.get("final_llm1_abstract_strategy"),
                    "final_llm1_concrete_strategy": item.get("final_llm1_concrete_strategy"),
                    "final_llm1_post_repair_state": item.get("final_llm1_post_repair_state")
                })

            if not vectors:
                print(f"CWE type {cwe_type} has no valid vectors, skipping")
                continue

            vectors = np.array(vectors).astype('float32')

            dimension = vectors.shape[1]
            index = faiss.IndexFlatL2(dimension)
            index.add(vectors)

            index_path = os.path.join(self.output_dir, f"{cwe_type}.index")
            metadata_path = os.path.join(self.output_dir, f"{cwe_type}_metadata.json")

            faiss.write_index(index, index_path)
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, ensure_ascii=False, indent=2)

            print(f"Created index for CWE type {cwe_type}, containing {len(vectors)} vectors")

    def build(self, strategy_analysis_output_paths):
        print(f"Starting to load data...")
        data = self.load_strategy_analysis_data(strategy_analysis_output_paths)

        print(f"Total {len(data)} records loaded")
        grouped_data = self.process_data(data)

        print(f"Found top-level parent CWE types: {list(grouped_data.keys())}")
        self.build_indices(grouped_data)
        print(f"All indices saved to {self.output_dir}")
