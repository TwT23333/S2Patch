import torch

from transformers import AutoTokenizer, AutoModel,T5EncoderModel
from typing import List, Dict, Union
import numpy as np
import os
from sentence_transformers import SentenceTransformer
np.random.seed(42)
torch.manual_seed(42)

# Root directory holding local embedding checkpoints; override via EMBED_MODEL_ROOT.
MODEL_ROOT = os.getenv("EMBED_MODEL_ROOT", "models")


class CodeEmbedder:
    def __init__(self, model_type: str = "bge-code-v1", device: str = "cuda:0"):
        self.model_type = model_type
        self.device = device
        if model_type == "codebert":
            self.dim = 768
        elif model_type == "xinference":
            self.dim = 1024
        elif model_type=='unixcoder':
            self.dim = 768
        elif model_type == "codet5":
            self.dim = 768
        elif model_type == "sfr":
            self.dim = 4096
        elif model_type == "gemini":
            self.dim = 3072
        elif model_type == "bge-code-v1":
            self.dim = 1024

        if model_type == "codebert":
            self.tokenizer = AutoTokenizer.from_pretrained(os.path.join(MODEL_ROOT, "graphcodebert"))
            self.model = AutoModel.from_pretrained(os.path.join(MODEL_ROOT, "graphcodebert")).to(device)
        elif model_type == "vllm":
            pass

        elif model_type == "xinference":
            from xinference.client import Client
            self.client = Client("http://localhost:9997")
            self.model = self.client.get_model("stella_en_1.5B_v5")
        elif model_type == "unixcoder":
            self.model = unixcoder.UniXcoder(os.path.join(MODEL_ROOT, "unixcoder")).to(device)
        elif model_type == "codet5":
            self.tokenizer = AutoTokenizer.from_pretrained(os.path.join(MODEL_ROOT, "codet5"),trust_remote_code=True)
            self.model = AutoModel.from_pretrained(os.path.join(MODEL_ROOT, "codet5")).to(device)
        elif model_type == "sfr":
            self.model = AutoModel.from_pretrained(os.path.join(MODEL_ROOT, "sfr_embed"), trust_remote_code=True)

        elif model_type == "gemini":

            from google import genai
            api_key = os.getenv("GEMINI_API_KEY")
            self.client = genai.Client(api_key=api_key)
            self.model_name = "gemini-embedding-exp-03-07"
        elif model_type == "bge-code-v1":
            model_kwargs = {"torch_dtype": torch.float16} if device == "cuda:0" else {}
            self.model = SentenceTransformer(
                os.path.join(MODEL_ROOT, "bge-code-v1"),
                trust_remote_code=True,
                model_kwargs=model_kwargs,
                device=device
            )
        else:
            raise ValueError(f"Unknown model type: {model_type}")
        if model_type not in ["gemini", "bge-code-v1"]:
            self.model.eval()

    def get_embeddings(self, code_snippets: List[str]) -> np.ndarray:
        if self.model_type == "codebert":
            return self._get_codebert_embeddings(code_snippets)
        elif self.model_type == "xinference":
            return self._get_xinfer_embeddings(code_snippets)
        elif self.model_type == "codet5":
            return self._get_codet5_embeddings(code_snippets)
        elif self.model_type == "sfr":
            return self._get_sfr_embeddings(code_snippets)
        elif self.model_type == "unixcoder":
            return self._get_unixcoder_embeddings(code_snippets)
        elif self.model_type == "gemini":
            return self._get_gemini_embeddings(code_snippets)
        elif self.model_type == "bge-code-v1":
            return self._get_bge_code_embeddings(code_snippets)

    def _get_unixcoder_embeddings(self, code_snippets: List[str]) -> np.ndarray:
        with torch.no_grad():
            tokens_ids = self.model.tokenize(code_snippets,max_length=512,mode="<encoder-only>",padding=True)
            source_ids = torch.tensor(tokens_ids).to(self.device)
            _,max_func_embedding = self.model(source_ids)
            return max_func_embedding.detach().cpu().numpy()

    def _get_codebert_embeddings(self, code_snippets: List[str]) -> np.ndarray:
        with torch.no_grad():
            inputs = self.tokenizer(
                code_snippets,
                padding=True,
                truncation=True,
                max_length=512,
                return_tensors="pt"
            ).to(self.device)

            outputs = self.model(**inputs)

            embeddings = outputs.last_hidden_state[:, 0, :].cpu().numpy()

        return embeddings

    def _get_sfr_embeddings(self, code_snippets: List[str]) -> np.ndarray:
        max_length = 32768

        embeddings = self.model.encode_corpus(code_snippets, max_length=max_length)
        return embeddings.cpu().numpy()

    def _get_xinfer_embeddings(self, code_snippets: List[str]) -> np.ndarray:

        outputs = self.model.create_embedding(code_snippets)

        embeddings = np.array([embedding['embedding'] for embedding in outputs['data']])
        return embeddings

    def _get_codet5_embeddings(self, code_snippets: List[str]) -> np.ndarray:
        with torch.no_grad():
            inputs = self.tokenizer(
                code_snippets,
                padding=True,
                truncation=True,
                max_length=512,
                return_tensors="pt"
            ).to(self.device)

            outputs = self.model.encoder(**inputs)

            last_hidden_state=outputs.last_hidden_state
            embeddings = torch.mean(last_hidden_state, dim=1)
            embeddings = embeddings.cpu().numpy()
        return embeddings

    def _get_gemini_embeddings(self, code_snippets: List[str]) -> np.ndarray:
        embeddings_list = []

        for snippet in code_snippets:
            result = self.client.models.embed_content(
                model=self.model_name,
                contents=snippet,
            )
            embeddings_list.append(result.embeddings[0].values)

        return np.array(embeddings_list)

    def _get_bge_code_embeddings(self, code_snippets: List[str]) -> np.ndarray:
        embeddings = self.model.encode(code_snippets)
        if isinstance(embeddings, torch.Tensor):
            embeddings = embeddings.cpu().numpy()
        elif not isinstance(embeddings, np.ndarray):
            embeddings = np.array(embeddings)

        return embeddings

if __name__ == "__main__":

    test_code_snippets = [
        """
def calculate_fibonacci(n):
    if n <= 0:
        return 0
    elif n == 1:
        return 1
    else:
        return calculate_fibonacci(n-1) + calculate_fibonacci(n-2)
        """,
        """
asdif x > pivot]
    return quick_sort(left) + middle + quick_sort(right)
        """
    ]

    print("Testing bge-code-v1 embedding model...")

    embedder = CodeEmbedder(model_type="bge-code-v1", device="cpu")
    embeddings = embedder.get_embeddings(test_code_snippets)

    print(f"Embedding dimensions: {embeddings.shape}")
    print(f"Values of first 5 dimensions: {embeddings[0][:5]}")


    from sklearn.metrics.pairwise import euclidean_distances
    distance = euclidean_distances([embeddings[0]], [embeddings[1]])[0][0]
    print(f"L2 distance between two code snippets: {distance:.4f}")

    print("\nTest completed!")
