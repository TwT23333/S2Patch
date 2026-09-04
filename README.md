# S²Patch: Syntactic-Semantic Pattern Learning for Automated Vulnerability Repair

S²Patch is an automated vulnerability repair (AVR) framework built around a generalized
**syntactic-semantic repair pattern base** mined from historical vulnerability fixes.
Each pattern couples an AST edit script with a semantic repair intent (root cause,
repair action, expected effect). The pattern base guides LLM-based patch synthesis and
can serve as an external repair memory for LLM coding agents.

## Repository Layout

```
astbase/                  # Syntactic side: GumTree AST diffing (AST.py), pattern
                          #   extraction (Pattern.py, run_parse.py), dendrogram
                          #   generalization (Hierarchical.py, run_cluster.py)
slicer/                   # Inter-procedural slicing on Joern output
models/                   # LLM backends (OpenAI-compatible / Gemini / vLLM) and
                          #   embedding models (embedding_helper.py)
utils/                    # CWE partitioning (CWE-1000 view v4.5), CSV helpers
vectorbase/               # FAISS retrieval; indices/ ships the prebuilt pattern base,
                          #   one index per CWE partition
datasets/                 # extractfix / APPatch / Zeroday benchmark CSVs
csv_strategy_analyzer.py  # Offline: semantic intent extraction + refinement
index_builder.py          # Offline: build per-CWE FAISS indices
inference.py              # Online: pattern-guided repair pipeline
```

## Requirements

```bash
pip install -r requirements.txt
```

Two external tools are needed:

- **GumTree** with **srcML** (the C grammar is invoked as `gumtree parse -g c-srcml`),
  available on `PATH`.
- **Joern**: place a distribution whose `joern-parse` produces the CSV export
  (`parsed/.../nodes.csv`, `edges.csv`) under `slicer/joern/`.

A GPU is only needed for local embedding models or vLLM serving; with remote APIs the
pipeline runs on CPU.

## Configuration

LLM calls take a `model_config` dict; an empty `api_key` falls back to the
`<PROVIDER>_API_KEY` environment variable:

```python
model_config = {
    "provider": "openai",             # any OpenAI-compatible provider
    "model_name": "<model snapshot>",
    "base_url": "<endpoint URL>",     # e.g. https://api.deepseek.com
    "api_key": "",                    # empty -> read <PROVIDER>_API_KEY
}
```

```bash
export DEEPSEEK_API_KEY=...   # used by astbase/ pattern generalization
export OPENAI_API_KEY=...     # or OPENROUTER_API_KEY / GEMINI_API_KEY, per provider
```

Backbones used in our experiments: Claude-3.5-Sonnet, DeepSeek-V3-0324, and
Llama-3.3-70B-Instruct (via vLLM); temperature 0.5 for candidate generation, 0.1 for
patch integration.

**Embeddings.** `CodeEmbedder` (`models/embedding_helper.py`) loads local checkpoints
from `$EMBED_MODEL_ROOT/<name>` (default `models/`). Building and querying the indices
must use the same embedding model (we use `jina-embeddings-v2-base-code`); if you switch models,
regenerate everything under `vectorbase/indices/`.

## Data

Benchmark CSVs in `datasets/` share the schema `code_before, code_after, CWE ID,
CVE ID`; `Zeroday/` is the 2025 pool from which S²Vuln is curated.

## Usage

### Repair with the shipped pattern base

Configure a backend (above). The defaults in `main()` of `inference.py` already target
`datasets/APPatch` with the shipped indices and the paper settings (5 hypothesized root
causes, k = 5 retrieved patterns each, post-state filtering, clustering + integration,
Top-5 output):

```bash
python inference.py
```

Switch `dataset` in `main()` to `extractfix` / `Zeroday` for the other benchmarks, or
point `csv_file_path` at a one-row CSV (schema above) to repair a single vulnerability.

Results are appended to `datasets/<name>/results_output.json` as JSON Lines: per
vulnerability, the hypothesized root causes, retrieved patterns, and all candidates
with filtering decisions.

### Rebuilding the pattern base

```bash
# 1. Semantic intents (root cause / action / effect); edit dataset & model at the
#    bottom of the script
python csv_strategy_analyzer.py

# 2. Syntactic edit patterns via GumTree; edit paths at the bottom of the script
cd astbase
python run_parse.py

# 3. Dendrogram construction (llm=True enables the semantic-coherence merge check)
mkdir -p clusters
python run_cluster.py
cd ..

# 4. Build per-CWE FAISS indices
python -c "from index_builder import VectorDatabaseBuilder; \
VectorDatabaseBuilder().build( \
  ['datasets/<name>/outputs/strategy_analysis_verbose/strategy_analysis_output.json'])"
```
