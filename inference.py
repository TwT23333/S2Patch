import faiss
from typing import List, Optional, Dict, Tuple, Set
import networkx as nx
from utils.graphslice_analyzer import analyze_code_diff

from grakel.kernels import WeisfeilerLehman
from grakel import graph_from_networkx
import re
import json
import difflib
import csv
import concurrent.futures
import threading
import multiprocessing
import enum
import os
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.cluster import AgglomerativeClustering
from slicer.parse_joern_output2 import slice_code_from_string
from utils.cwe_find import CWEProcessor
from vectorbase.query_index import VectorDatabaseQuerier
from models.OpenAI_API import generate_with_OpenAI_model

from utils.graphslice_analyzer import analyze_code_diff
import math
import subprocess
import tempfile
from pathlib import Path
csv.field_size_limit(10000000)


class EvaluationResult(enum.Enum):
    SYNTACTIC_PATCH_EQUIVALENT = "SynPatchEq"
    SEMANTIC_EQUIVALENT = "SemEq"
    PLAUSIBLE = "Plausible"
    INCORRECT = "Incorrect"
    UNKNOWN = "Unknown"


class RootCauseConsistency(enum.Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INCONSISTENT = "Inconsistent"


PATCH_GROUPING_CONFIG = {
    "embedding_similarity_threshold": 0.9,
    "keyword_similarity_threshold": 0.7,
    "min_group_size": 2,
    "max_groups": 4,
    "enhancement_priority_boost": 0.1,
    "weight_patch_embedding": 0.4,
    "weight_keyword_similarity": 0.2,
    "weight_strategy_embedding": 0.4
}

DEFAULT_OPENAI_PARAMS = {

    "temperature": 0,
    "n": 1
}

MAIN_CWE_TYPES_FOR_INDEXING = [
    "CWE-189", "CWE-254", "CWE-264", "CWE-284", "CWE-310",
    "CWE-399", "CWE-664", "CWE-682", "CWE-691", "CWE-703", "CWE-707"
]

thread_local_data = threading.local()


def get_thread_local_instances():
    if not hasattr(thread_local_data, 'cwe_processor'):
        thread_local_data.cwe_processor = CWEProcessor()
        thread_local_data.vector_querier = VectorDatabaseQuerier(indices_dir="vectorbase/indices")

    return thread_local_data.cwe_processor, thread_local_data.vector_querier


def calculate_patch_embedding_similarity(patch1: str, patch2: str, embedder, verbose: bool = False) -> float:
    try:
        if not patch1.strip() or not patch2.strip():
            return 0.0

        embedding1 = embedder.encode([patch1])
        embedding2 = embedder.encode([patch2])

        similarity = cosine_similarity(embedding1, embedding2)[0][0]

        if verbose:
            print(f"      Patch embedding similarity: {similarity:.4f}")

        return float(similarity)

    except Exception as e:
        if verbose:
            print(f"      Error: Failed to calculate patch embedding similarity - {e}")
        return 0.0


def calculate_keyword_similarity(keywords1: List[str], keywords2: List[str], verbose: bool = False) -> float:
    try:
        if not keywords1 or not keywords2:
            return 0.0

        text1 = " ".join(keywords1)
        text2 = " ".join(keywords2)

        if not text1.strip() or not text2.strip():
            return 0.0

        vectorizer = TfidfVectorizer(lowercase=True, token_pattern=r'\b\w+\b')
        try:
            tfidf_matrix = vectorizer.fit_transform([text1, text2])
            similarity = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])[0][0]
        except ValueError:

            return 0.0

        if verbose:
            print(f"      Keyword similarity: {similarity:.4f}")

        return float(similarity)

    except Exception as e:
        if verbose:
            print(f"      Error: Failed to calculate keyword similarity - {e}")
        return 0.0


def group_patches_by_similarity(
    repair_suggestions: List[dict],
    embedder,
    config: dict = None,
    verbose: bool = False
) -> List[List[dict]]:
    if not repair_suggestions:
        return []

    if config is None:
        config = PATCH_GROUPING_CONFIG

    weight_patch_embedding = config.get("weight_patch_embedding", 0.5)
    weight_keyword_similarity = config.get("weight_keyword_similarity", 0.2)
    weight_strategy_embedding = config.get("weight_strategy_embedding", 0.3)

    if verbose:
        print(f"  Starting similarity grouping for {len(repair_suggestions)} patches (weights: PatchEmb={weight_patch_embedding}, Keyword={weight_keyword_similarity}, StrategyEmb={weight_strategy_embedding})...")

    if len(repair_suggestions) < config["min_group_size"]:
        if verbose:
            print(f"    Patch count ({len(repair_suggestions)}) is less than minimum group size ({config['min_group_size']}), skipping grouping")
        return [repair_suggestions]

    n_patches = len(repair_suggestions)
    similarity_matrix = np.zeros((n_patches, n_patches))

    for i in range(n_patches):
        for j in range(i + 1, n_patches):
            patch1 = repair_suggestions[i].get("suggestion_patch", "")
            patch2 = repair_suggestions[j].get("suggestion_patch", "")
            keywords1 = repair_suggestions[i].get("key_variables", [])
            keywords2 = repair_suggestions[j].get("key_variables", [])
            strategy1_text = repair_suggestions[i].get("repair_strategy", "")
            strategy2_text = repair_suggestions[j].get("repair_strategy", "")

            embedding_sim = calculate_patch_embedding_similarity(
                patch1, patch2, embedder, verbose=False
            )

            keyword_sim = calculate_keyword_similarity(
                keywords1, keywords2, verbose=False
            )

            strategy_sim = calculate_patch_embedding_similarity(
                strategy1_text, strategy2_text, embedder, verbose=False
            )

            combined_sim = (
                weight_patch_embedding * embedding_sim +
                weight_keyword_similarity * keyword_sim +
                weight_strategy_embedding * strategy_sim
            )

            similarity_matrix[i][j] = combined_sim
            similarity_matrix[j][i] = combined_sim

    distance_matrix = 1.0 - similarity_matrix

    try:

        max_clusters = min(config["max_groups"], n_patches)
        best_n_clusters = 1
        best_silhouette = -1

        for n_clusters in range(2, max_clusters + 1):
            clustering = AgglomerativeClustering(
                n_clusters=n_clusters,
                metric='precomputed',
                linkage='average'
            )
            cluster_labels = clustering.fit_predict(distance_matrix)

            group_quality = 0.0
            for cluster_id in range(n_clusters):
                cluster_indices = np.where(cluster_labels == cluster_id)[0]
                if len(cluster_indices) >= config["min_group_size"]:

                    group_similarities = []
                    for i in cluster_indices:
                        for j in cluster_indices:
                            if i != j:
                                group_similarities.append(similarity_matrix[i][j])
                    if group_similarities:
                        avg_sim = np.mean(group_similarities)
                        group_quality += avg_sim

            if group_quality > best_silhouette:
                best_silhouette = group_quality
                best_n_clusters = n_clusters

        clustering = AgglomerativeClustering(
            n_clusters=best_n_clusters,
            metric='precomputed',
            linkage='average'
        )
        cluster_labels = clustering.fit_predict(distance_matrix)

        groups = []
        for cluster_id in range(best_n_clusters):
            cluster_indices = np.where(cluster_labels == cluster_id)[0]
            if len(cluster_indices) >= config["min_group_size"]:
                group = [repair_suggestions[i] for i in cluster_indices]
                groups.append(group)
            else:

                if groups:
                    largest_group_idx = max(range(len(groups)), key=lambda x: len(groups[x]))
                    for i in cluster_indices:
                        groups[largest_group_idx].append(repair_suggestions[i])
                else:

                    group = [repair_suggestions[i] for i in cluster_indices]
                    groups.append(group)

        if verbose:
            print(f"    Successfully divided into {len(groups)} groups:")
            for i, group in enumerate(groups):
                print(f"      Group {i+1}: {len(group)} patches")

                if len(group) > 1:
                    group_similarities = []
                    for j in range(len(group)):
                        for k in range(j + 1, len(group)):
                            patch_j = group[j].get("suggestion_patch", "")
                            patch_k = group[k].get("suggestion_patch", "")
                            keywords_j = group[j].get("key_variables", [])
                            keywords_k = group[k].get("key_variables", [])
                            strategy_j_text = group[j].get("repair_strategy", "")
                            strategy_k_text = group[k].get("repair_strategy", "")

                            embedding_sim_group = calculate_patch_embedding_similarity(
                                patch_j, patch_k, embedder, verbose=False
                            )
                            keyword_sim_group = calculate_keyword_similarity(
                                keywords_j, keywords_k, verbose=False
                            )
                            strategy_sim_group = calculate_patch_embedding_similarity(
                                strategy_j_text, strategy_k_text, embedder, verbose=False
                            )
                            combined_sim_group = (
                                weight_patch_embedding * embedding_sim_group +
                                weight_keyword_similarity * keyword_sim_group +
                                weight_strategy_embedding * strategy_sim_group
                            )
                            group_similarities.append(combined_sim_group)

                    if group_similarities:
                        avg_sim = np.mean(group_similarities)
                        print(f"        Average intra-group similarity: {avg_sim:.4f}")

        return groups

    except Exception as e:
        if verbose:
            print(f"    Error: Clustering grouping failed - {e}, returning single group")
        return [repair_suggestions]


def generate_enhanced_patch_for_group(
    group_patches: List[dict],
    vulnerable_code: str,
    cwe_id: str,
    vulnerable_line_numbers: List[int],
    group_id: int,
    model_config: dict,
    verbose: bool = False
) -> Optional[dict]:
    if not group_patches:
        return None

    if verbose:
        print(f"    Generating enhanced patch for group {group_id} (containing {len(group_patches)} original patches)...")

    all_patches = []
    all_strategies = []
    all_key_variables = set()
    all_root_causes = []

    for patch_data in group_patches:
        patch = patch_data.get("suggestion_patch", "")
        strategy = patch_data.get("repair_strategy", "")
        key_vars = patch_data.get("key_variables", [])
        root_cause = patch_data.get("source_root_cause_desc", "")

        if patch.strip():
            all_patches.append(patch)
        if strategy.strip():
            all_strategies.append(strategy)
        if key_vars:
            all_key_variables.update(key_vars)
        if root_cause.strip():
            all_root_causes.append(root_cause)

    if not all_patches:
        if verbose:
            print(f"      Warning: No valid patches in group {group_id}")
        return None

    patches_section = ""
    for i, patch in enumerate(all_patches):
        patches_section += f"\n**Patch {i+1}:**\n```diff\n{patch}\n```\n"

    strategies_section = ""
    for i, strategy in enumerate(all_strategies):
        strategies_section += f"\n**Strategy {i+1}:** {strategy}\n"

    key_variables_list = list(all_key_variables)
    root_causes_section = ""
    for i, root_cause in enumerate(set(all_root_causes)):
        root_causes_section += f"\n**Root Cause {i+1}:** {root_cause}\n"

    formatted_vulnerable_lines = format_lines_with_statements(vulnerable_code, vulnerable_line_numbers)
    enhancement_prompt = f"""
You are an expert security code repair specialist. Your task is to analyze multiple patch proposals for the same vulnerability and synthesize a superior, more precise patch by following a structured three-step process.

**Original Vulnerable Code (CWE: {cwe_id}):**
```
{add_line_numbers_to_code(vulnerable_code)}
```

**Vulnerable Lines:**
{formatted_vulnerable_lines}

**Multiple Patch Proposals to Analyze:**
{patches_section}

**Repair Strategies from Proposals:**
{strategies_section}

**Candidate Root Causes:**
{root_causes_section}

**Patch Enhancement Task (Follow these three steps meticulously):**

**Step 1: Identify Core Repair Logic and Consolidate Comprehensive Repair Patterns**
- For each patch proposal, meticulously identify its **core vulnerability-fixing logic**.
- When **identical vulnerability-fixing logic** is found across multiple patches, select the **most appropriate, precise, concise, and robust** repair pattern among them.
- When **different vulnerability-fixing logic** is identified, critically analyze whether each piece of logic is **necessary and beneficial** for a comprehensive fix. If so, integrate these varied logics thoughtfully.
- Combine the selected and integrated core repair logics to form one or more **comprehensive repair patterns** that effectively address the vulnerability.

**Step 2: Analyze and Eliminate Irrelevant Modification Patterns**
- Scrutinize all patch proposals to identify any modification patterns that are **not directly related to fixing the identified vulnerability**. These could include stylistic changes, unrelated refactoring, or other non-essential code alterations.
- **Decisively remove these redundant or irrelevant modifications**. The goal is to isolate changes that purely address the security issue.

**Step 3: Optimize Patch with Project-Specific Code Characteristics**
- Based on the refined and consolidated repair patterns from Step 1 and the elimination of irrelevant changes from Step 2, proceed to optimize the final patch.
- Leverage the **unique code characteristics of the project** where the vulnerable code resides. This includes, but is not limited to:
    - Specific **APIs** commonly used within the project.
    - Project-defined **macro definitions**.
    - Prevailing **identifier naming conventions** (for variables, functions, etc.).
    - Typical **pointer usage patterns** and **struct/class definitions** specific to the codebase.
- Adapt the patch to seamlessly align with these project-specific characteristics. This ensures the patch is not only correct but also well-integrated, maintainable, and robust within the context of the existing codebase.

**Output Format:**
Please provide your response in the following structured format:

PATTERN_ANALYSIS_START:
[Describe the comprehensive repair pattern(s) you identified and consolidated in Step 1. Explain the core logic and why it's effective.]
PATTERN_ANALYSIS_END:

PRECISION_ANALYSIS_START:
[Explain how you ensured the fix is precise and minimal, detailing the core logic selected/integrated from Step 1 and how irrelevant modifications were handled in Step 2.]
PRECISION_ANALYSIS_END:

IRRELEVANT_MODIFICATIONS_START:
[List any significant modification patterns found in the original proposals that you identified as irrelevant to the vulnerability fix and consequently removed in Step 2. Explain briefly why they were deemed irrelevant.]
IRRELEVANT_MODIFICATIONS_END:

NEW_IDEA_START:
[If, during Step 3 (optimization with project-specific characteristics) or your overall analysis, you developed any novel approaches or significant improvements not directly derivable from the input patches, describe them here. Otherwise, state "No new ideas beyond synthesis and optimization."]
NEW_IDEA_END:

SYNTHESIS_SUMMARY_START:
[Provide a concise summary of your synthesis process following the three steps:
1. How core repair logics were identified and consolidated.
2. How irrelevant modifications were eliminated.
3. How project-specific code characteristics were used to optimize the final patch.]
SYNTHESIS_SUMMARY_END:

SECURITY_ANALYSIS_START:
[Analyze how the synthesized patch, developed through the three-step process, provides robust security coverage for the identified vulnerability, potentially being superior to individual proposals.]
SECURITY_ANALYSIS_END:

KEY_VARIABLES_START:
[List the key variables, functions, or crucial program elements that are central to the **final synthesized patch**, separated by commas.]
KEY_VARIABLES_END:

ENHANCEMENT_STRATEGY_START:
[Explain your overall enhancement strategy based on the three steps:
- Step 1 (Consolidation): Detail the logic for choosing and integrating repair patterns.
- Step 2 (Elimination): Justify the removal of irrelevant changes.
- Step 3 (Optimization): Describe how project-specifics improved the patch.
Conclude why this structured approach yields a superior, precise, and well-integrated security patch.]
ENHANCEMENT_STRATEGY_END:

ENHANCED_PATCH_DIFF_START:
[Your synthesized unified diff patch. This patch must be the direct result of the three-step process, focusing exclusively on the essential security fix, demonstrating precision, and incorporating project-specific optimizations.]
ENHANCED_PATCH_DIFF_END:
"""

    try:

        api_call_params = {
            "prompt": enhancement_prompt,
            "model_config": model_config,
            "max_tokens": 16000,
            "temperature": DEFAULT_OPENAI_PARAMS.get("temperature", 0),
            "n": DEFAULT_OPENAI_PARAMS.get("n", 1)
        }

        response_list = generate_with_OpenAI_model(**api_call_params)

        if not response_list or not response_list[0]:
            if verbose:
                print(f"      Error: LLM did not return valid response (group {group_id})")
            return None

        response_text = response_list[0].strip()

        enhanced_patch = None
        enhancement_strategy = None
        security_analysis = None
        key_variables = []
        pattern_analysis = None
        precision_analysis = None
        irrelevant_modifications = None
        synthesis_summary = None

        pattern_match = re.search(r'PATTERN_ANALYSIS_START:\s*(.*?)\s*PATTERN_ANALYSIS_END:', response_text, re.DOTALL)
        if pattern_match:
            pattern_analysis = pattern_match.group(1).strip()

        precision_match = re.search(r'PRECISION_ANALYSIS_START:\s*(.*?)\s*PRECISION_ANALYSIS_END:', response_text, re.DOTALL)
        if precision_match:
            precision_analysis = precision_match.group(1).strip()

        irrelevant_match = re.search(r'IRRELEVANT_MODIFICATIONS_START:\s*(.*?)\s*IRRELEVANT_MODIFICATIONS_END:', response_text, re.DOTALL)
        if irrelevant_match:
            irrelevant_modifications = irrelevant_match.group(1).strip()

        patch_match = re.search(r'ENHANCED_PATCH_DIFF_START:\s*(.*?)\s*ENHANCED_PATCH_DIFF_END:', response_text, re.DOTALL)
        if patch_match:
            enhanced_patch = patch_match.group(1).strip()

        strategy_match = re.search(r'ENHANCEMENT_STRATEGY_START:\s*(.*?)\s*ENHANCEMENT_STRATEGY_END:', response_text, re.DOTALL)
        if strategy_match:
            enhancement_strategy = strategy_match.group(1).strip()

        security_match = re.search(r'SECURITY_ANALYSIS_START:\s*(.*?)\s*SECURITY_ANALYSIS_END:', response_text, re.DOTALL)
        if security_match:
            security_analysis = security_match.group(1).strip()

        variables_match = re.search(r'KEY_VARIABLES_START:\s*(.*?)\s*KEY_VARIABLES_END:', response_text, re.DOTALL)
        if variables_match:
            variables_text = variables_match.group(1).strip()
            if variables_text:
                key_variables = [var.strip() for var in variables_text.split(',') if var.strip()]

        synthesis_match = re.search(r'SYNTHESIS_SUMMARY_START:\s*(.*?)\s*SYNTHESIS_SUMMARY_END:', response_text, re.DOTALL)
        if synthesis_match:
            synthesis_summary = synthesis_match.group(1).strip()

        if not enhanced_patch or not enhanced_patch.strip():
            if verbose:
                print(f"      Error: Enhanced patch is empty (group {group_id})")
            return None

        if not enhancement_strategy or not enhancement_strategy.strip():
            if verbose:
                print(f"      Error: Enhancement strategy is empty (group {group_id})")
            return None

        enhanced_suggestion = {
            "suggestion_patch": enhanced_patch,
            "repair_strategy": enhancement_strategy,
            "key_variables": key_variables,
            "source_root_cause_desc": f"Enhanced from group {group_id} ({len(group_patches)} patches)",
            "source_example_pre_repair_state": "Enhanced patch - multiple examples combined",
            "source_example_post_repair_state": security_analysis or "Enhanced security patch",
            "source_example_code_before": "N/A",
            "source_example_code_after": "N/A",
            "source_example_distance": -2.0,
            "llm_score": 1.0 + PATCH_GROUPING_CONFIG["enhancement_priority_boost"],
            "repair_method": "enhanced_group",
            "group_id": group_id,
            "original_patches_count": len(group_patches),
            "security_analysis": security_analysis,
            "pattern_analysis": pattern_analysis,
            "precision_analysis": precision_analysis,
            "irrelevant_modifications": irrelevant_modifications,
            "synthesis_summary": synthesis_summary
        }

        if verbose:
            print(f"      Successfully generated enhanced patch for group {group_id}")
            print(f"      Enhancement strategy: {enhancement_strategy[:100]}...")
            print(f"      Key variables: {key_variables}")

        return enhanced_suggestion

    except Exception as e:
        if verbose:
            print(f"      Error: Exception occurred while generating enhanced patch for group {group_id} - {e}")
        return None


def apply_patch_grouping_enhancement(
    repair_suggestions: List[dict],
    vulnerable_code: str,
    cwe_id: str,
    vulnerable_line_numbers: List[int],
    model_config: dict,
    enable_patch_grouping: bool = False,
    config: dict = None,
    verbose: bool = False
) -> List[dict]:
    if not enable_patch_grouping or not repair_suggestions:
        return repair_suggestions

    if config is None:
        config = PATCH_GROUPING_CONFIG

    if verbose:
        print(f"  Enabling patch grouping enhancement algorithm...")

    try:
        _, vector_querier = get_thread_local_instances()
        embedder = vector_querier.embedder
    except Exception as e:
        if verbose:
            print(f"    Error: Unable to get embedder instance - {e}, skipping grouping enhancement")
        return repair_suggestions

    patch_groups = group_patches_by_similarity(
        repair_suggestions=repair_suggestions,
        embedder=embedder,
        config=config,
        verbose=verbose
    )

    if len(patch_groups) <= 1:
        if verbose:
            print(f"    Patches could not be effectively grouped (group count: {len(patch_groups)}), skipping enhancement")
        return repair_suggestions

    enhanced_patches_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        future_to_group_id = {}
        for group_id, group_patches in enumerate(patch_groups):
            if len(group_patches) >= config["min_group_size"]:
                future = executor.submit(generate_enhanced_patch_for_group,
                                         group_patches=group_patches,
                                         vulnerable_code=vulnerable_code,
                                         cwe_id=cwe_id,
                                         vulnerable_line_numbers=vulnerable_line_numbers,
                                         group_id=group_id + 1,
                                         model_config=model_config,
                                         verbose=verbose)
                future_to_group_id[future] = group_id + 1

        for future in concurrent.futures.as_completed(future_to_group_id):
            original_group_id = future_to_group_id[future]
            try:
                enhanced_patch = future.result()
                if enhanced_patch:
                    enhanced_patches_results.append((original_group_id, enhanced_patch))
            except Exception as exc:
                if verbose:
                    print(f"    Error: Exception occurred while generating enhanced patch for group {original_group_id} (executor): {exc}")

    enhanced_patches_results.sort(key=lambda x: x[1].get('original_patches_count', 0), reverse=True)
    enhanced_patches = [item[1] for item in enhanced_patches_results]

    if not enhanced_patches:
        if verbose:
            print(f"    Failed to generate any enhanced patches, returning original suggestions")
        return repair_suggestions

    if verbose:
        print(f"    Successfully generated {len(enhanced_patches)} enhanced patches, adding them to the front of candidate list")

    final_suggestions = enhanced_patches + repair_suggestions

    return final_suggestions


SIMILARITY_THRESHOLD = 0.6


def get_graph_for_code(repaired_code_string: str, original_code_string: str, verbose: bool = False) -> Optional[nx.DiGraph]:
    if not repaired_code_string:
        if verbose:
            print("  get_graph_for_code: Repaired code string is empty.")
        return None

    _, added_or_modified_lines_new = analyze_code_diff(original_code_string, repaired_code_string)

    if not added_or_modified_lines_new:
        if verbose:
            print("  get_graph_for_code: No added or modified lines found between original and repaired code. Cannot generate focused graph.")

        return None

    try:
        if verbose:
            print(f"  get_graph_for_code: Slicing repaired code based on {len(added_or_modified_lines_new)} changed lines: {added_or_modified_lines_new}")

        _sliced_code_str, graph = slice_code_from_string(
            source_code=repaired_code_string,
            target_lines=added_or_modified_lines_new,
            slice_type="combined",
            data_flow_only=True,
            verbose=verbose,
            return_graph=True,
            graph_detail_level='slice',
            program_graph_edge_types='ddg'
        )
        if graph is not None and isinstance(graph, nx.DiGraph):
            if verbose:
                print(f"  get_graph_for_code: Successfully generated graph with {graph.number_of_nodes()} nodes and {graph.number_of_edges()} edges.")
            return graph
        else:
            if verbose:
                print("  get_graph_for_code: slice_code_from_string did not return a valid graph.")
            return None
    except Exception as e:
        if verbose:
            print(f"  get_graph_for_code: Error during slice_code_from_string: {e}")
        return None


def map_key_variables_to_node_ids(graph: nx.DiGraph, key_variables: List[str], verbose: bool = False) -> List[str]:
    matched_node_ids: Set[str] = set()
    if not key_variables or graph.number_of_nodes() == 0:
        return []

    normalized_key_vars = [kv.replace(" ", "").lower() for kv in key_variables if kv]

    for node_id, attrs in graph.nodes(data=True):
        node_code_str = str(attrs.get('code', ''))
        node_name_str = str(attrs.get('name', ''))

        normalized_node_code = node_code_str.replace(" ", "").lower()
        normalized_node_name = node_name_str.replace(" ", "").lower()

        for nk_var in normalized_key_vars:
            if (normalized_node_code and nk_var in normalized_node_code) or \
               (normalized_node_name and nk_var in normalized_node_name):
                matched_node_ids.add(str(node_id))

                break

    return sorted(list(matched_node_ids))


def extract_subgraph_for_variables(focused_graph: nx.DiGraph, target_node_ids: List[str], verbose: bool = False) -> Optional[nx.DiGraph]:
    if not target_node_ids or focused_graph.number_of_nodes() == 0:
        if verbose:
            print("  extract_subgraph_for_variables: No target node IDs or graph is empty.")
        return None

    nodes_for_subgraph: Set[str] = set()

    valid_target_node_ids = [nid for nid in target_node_ids if nid in focused_graph]
    if not valid_target_node_ids:
        if verbose:
            print(f"  extract_subgraph_for_variables: None of the target_node_ids {target_node_ids} found in the graph.")
        return None

    for node_id in valid_target_node_ids:
        nodes_for_subgraph.add(node_id)

        nodes_for_subgraph.update(map(str, focused_graph.predecessors(node_id)))
        nodes_for_subgraph.update(map(str, focused_graph.successors(node_id)))

    final_nodes_for_subgraph = {nid for nid in nodes_for_subgraph if nid in focused_graph}

    if not final_nodes_for_subgraph:
        if verbose:
            print("  extract_subgraph_for_variables: Resulting node set for subgraph is empty.")
        return None

    subgraph = focused_graph.subgraph(final_nodes_for_subgraph).copy()
    if verbose:
        print(f"  extract_subgraph_for_variables: Extracted subgraph with {subgraph.number_of_nodes()} nodes and {subgraph.number_of_edges()} edges.")
    return subgraph


def calculate_graph_similarity(graph1: nx.DiGraph, graph2: nx.DiGraph, verbose: bool = False) -> float:
    if graph1 is None or graph2 is None:
        if verbose:
            print("  calculate_graph_similarity: One or both graphs are None. Returning 0.0 similarity.")
        return 0.0
    if graph1.number_of_nodes() == 0 and graph2.number_of_nodes() == 0:
        if verbose:
            print("  calculate_graph_similarity: Both graphs are empty (0 nodes). Returning 1.0 similarity (identical empty graphs).")
        return 1.0
    if graph1.number_of_nodes() == 0 or graph2.number_of_nodes() == 0:
        if verbose:
            print("  calculate_graph_similarity: One graph is empty, the other is not. Returning 0.0 similarity.")
        return 0.0

    try:

        processed_graphs = []
        for g_idx, g_orig in enumerate([graph1, graph2]):
            g_copy = g_orig.copy()
            for node_id, attributes in g_copy.nodes(data=True):
                label_part = attributes.get('_label', 'NOLABEL')
                code_part = attributes.get('code', 'NOCODE')

                attributes['combined_label'] = f"{str(label_part)}_{str(code_part)}"
            processed_graphs.append(g_copy)

        gk_graphs = graph_from_networkx(
            processed_graphs,
            node_labels_tag='combined_label',
            edge_labels_tag='flow_type'
        )

        try:
            gk = WeisfeilerLehman(n_iter=5, normalize=True, verbose=verbose, n_jobs=-1)
        except TypeError:
            gk = WeisfeilerLehman(n_iter=5, normalize=True)

        kernel_matrix = gk.fit_transform(gk_graphs)
        similarity = kernel_matrix[0, 1]

        if verbose:
            print(f"  calculate_graph_similarity: Weisfeiler-Lehman kernel similarity = {similarity:.4f}")
        return similarity

    except Exception as e:
        if verbose:
            print(f"  calculate_graph_similarity: Error during Weisfeiler-Lehman kernel calculation: {e}. Returning 0.0.")
        return 0.0


def identify_key_variables_and_generate_focused_slice(
    vulnerable_code: str,
    cwe_id: str,
    vulnerable_line_numbers: List[int],
    model_config: dict,
    verbose: bool = False
) -> Tuple[str, List[int], List[dict]]:
    code_before_numbered = add_line_numbers_to_code(vulnerable_code)
    formatted_vulnerable_lines = format_lines_with_statements(vulnerable_code, vulnerable_line_numbers)

    prompt_identify_key_variables = f"""Analyze the following vulnerable code to identify key variables, functions, and program elements that are most relevant to the {cwe_id} vulnerability.

CWE Type: {cwe_id}
Vulnerable Lines (approximate):
{formatted_vulnerable_lines}

Vulnerable Code:
```
{code_before_numbered}
```

Task: Identify the most important variables, functions, and program elements that are directly related to the vulnerability. Focus on:
1. Variables that handle user input or external data
2. Functions that process or validate data
3. Control flow elements that affect security
4. Any other critical elements specific to {cwe_id} vulnerabilities

For each identified element, provide the specific line numbers where they appear in the vulnerable code.

Output STRICTLY in the following JSON format:
```json
{{
  "key_elements": [
    {{"name": "variable_or_function_name", "lines": [line_num1, line_num2], "type": "variable|function|operation", "relevance": "brief description of why this is relevant to the vulnerability"}},
    ...
  ]
}}
```

Focus on the most critical elements - typically 3-8 key elements should be sufficient to capture the vulnerability's essence.
"""

    key_variable_lines = []
    key_elements_info = []

    try:
        api_call_params_key_vars = {
            "prompt": prompt_identify_key_variables,
            "model_config": model_config,
            "max_tokens": 3000,
            "temperature": DEFAULT_OPENAI_PARAMS.get("temperature", 0),
            "n": DEFAULT_OPENAI_PARAMS.get("n", 1)
        }
        response_text_key_vars_list = generate_with_OpenAI_model(**api_call_params_key_vars)

        if response_text_key_vars_list and response_text_key_vars_list[0]:
            response_text_key_vars = response_text_key_vars_list[0]

            json_match = re.search(r'```json\s*([\s\S]*?)\s*```', response_text_key_vars)
            if not json_match:
                json_match = re.search(r'({[\s\S]*})', response_text_key_vars)

            if json_match:
                json_str = json_match.group(1)
                try:
                    parsed_response = json.loads(json_str)
                    if "key_elements" in parsed_response and isinstance(parsed_response["key_elements"], list):
                        for element in parsed_response["key_elements"]:
                            if element.get("lines") and isinstance(element["lines"], list):
                                key_variable_lines.extend(element["lines"])
                                key_elements_info.append(element)

                        key_variable_lines = sorted(list(set(key_variable_lines)))
                        if verbose:
                            print(f"Identified key variable related line numbers: {key_variable_lines}")
                    else:
                        if verbose:
                            print(f"Warning: LLM did not return key variable information in expected format. Response: {response_text_key_vars}")
                except json.JSONDecodeError as je:
                    if verbose:
                        print(f"Warning: JSON decoding failed when parsing LLM key variable response: {je}. Response: {response_text_key_vars}")
            else:
                if verbose:
                    print(f"Warning: No JSON block found in LLM key variable response. Response: {response_text_key_vars}")
        else:
            if verbose:
                print("Warning: LLM failed to generate key variable analysis.")

    except Exception as e:
        if verbose:
            print(f"Error: Exception occurred while identifying key variables - {e}")

    if not key_variable_lines:
        if verbose:
            print("Failed to identify key variable line numbers, using original vulnerable line numbers as fallback.")
        key_variable_lines = vulnerable_line_numbers

    focused_code_slice = ""
    try:
        focused_code_slice, _ = slice_code_from_string(
            source_code=vulnerable_code,
            target_lines=key_variable_lines,
            slice_type="combined",
            data_flow_only=False,
            verbose=False
        )
        if not focused_code_slice.strip():
            if verbose:
                print("Warning: Focused code slice generated based on key variables is empty. Using original code as fallback.")
            focused_code_slice = vulnerable_code
        else:
            if verbose:
                print(f"Successfully generated focused code slice (based on line numbers: {key_variable_lines})")
    except Exception as e:
        if verbose:
            print(f"Error: Failed to generate focused code slice - {e}. Using original code as fallback.")
        focused_code_slice = vulnerable_code

    return focused_code_slice, key_variable_lines, key_elements_info


def identify_root_causes_and_key_variables(
    vulnerable_code: str,
    cwe_id: str,
    vulnerable_line_numbers: List[int],
    model_config: dict,
    num_root_causes_to_analyze: int = 3,
    verbose: bool = False
) -> List[dict]:
    code_before_numbered = add_line_numbers_to_code(vulnerable_code)
    formatted_vulnerable_lines = format_lines_with_statements(vulnerable_code, vulnerable_line_numbers)

    prompt_identify_root_causes = f"""Analyze the following vulnerable code to identify potential root causes of the {cwe_id} vulnerability. For each root cause, provide three key aspects: the specific root cause, the abstract repair logic, and the expected effect after repair.

CWE Type: {cwe_id}
Vulnerable Lines (approximate):
{formatted_vulnerable_lines}

Vulnerable Code:
```
{code_before_numbered}
```

Task:
1. Identify up to {num_root_causes_to_analyze} distinct and most likely root causes for the vulnerability
2. For each root cause, provide:
   - specific_root_cause: The concrete root cause with specific variable names, function names, and line numbers
   - abstract_repair_logic: The generalized repair strategy that can be applied to similar vulnerabilities (without specific code details)
   - effect: The expected outcome after applying the repair, describing how the vulnerability is eliminated
3. Identify the key variables and line numbers relevant to each root cause
4. Ensure that the identified root causes are as diverse as possible
5. Consider the provided CWE ID and its typical characteristics
6. Every root cause should reason step by step from source to sink

Output STRICTLY in the following JSON format:
```json
{{
  "root_causes": [
    {{
      "id": 1,
      "specific_root_cause": "Concrete description of the root cause with specific variable names (e.g., 'ptr'), function names, and line numbers. Explain the vulnerability mechanism step by step from source to sink.",
      "abstract_repair_logic": "Generalized repair strategy without specific code details. E.g., 'Add null pointer validation before dereferencing' instead of 'Add if(ptr != NULL) check'.",
      "effect": "Expected outcome after repair. E.g., 'Ensures pointer validity before use, preventing null pointer dereference crashes'.",
      "key_variables": ["var1", "var2", "function1"],
      "key_variable_lines": [line_num1, line_num2, line_num3]
    }},
    {{
      "id": 2,
      "specific_root_cause": "Concrete description of root cause 2...",
      "abstract_repair_logic": "Generalized repair strategy 2...",
      "effect": "Expected outcome 2...",
      "key_variables": ["var3", "var4", "function2"],
      "key_variable_lines": [line_num4, line_num5, line_num6]
    }}
  ]
}}
```

Important: Each root cause should focus on different aspects of the vulnerability and have its own set of relevant lines and variables.
"""

    root_causes_with_variables = []

    try:
        api_call_params_root_cause = {
            "prompt": prompt_identify_root_causes,
            "model_config": model_config,
            "max_tokens": 5000,
            "temperature": DEFAULT_OPENAI_PARAMS.get("temperature", 0),
            "n": DEFAULT_OPENAI_PARAMS.get("n", 1)
        }
        response_text_root_cause_list = generate_with_OpenAI_model(**api_call_params_root_cause)

        if response_text_root_cause_list and response_text_root_cause_list[0]:
            response_text_root_cause = response_text_root_cause_list[0]

            json_match = re.search(r'```json\s*([\s\S]*?)\s*```', response_text_root_cause)
            if not json_match:
                json_match = re.search(r'({[\s\S]*})', response_text_root_cause)

            if json_match:
                json_str = json_match.group(1)
                try:
                    parsed_response = json.loads(json_str)
                    if "root_causes" in parsed_response and isinstance(parsed_response["root_causes"], list):
                        for rc in parsed_response["root_causes"]:
                            if rc.get("specific_root_cause") and rc.get("key_variable_lines"):

                                key_lines = []
                                try:
                                    key_lines = [int(line) for line in rc["key_variable_lines"] if isinstance(line, (int, str)) and str(line).isdigit()]
                                except (ValueError, TypeError):
                                    if verbose:
                                        print(f"Warning: Root cause {rc.get('id', 'unknown')} key_variable_lines format error, using original vulnerable line numbers")
                                    key_lines = vulnerable_line_numbers

                                if not key_lines:
                                    key_lines = vulnerable_line_numbers

                                root_causes_with_variables.append({
                                    "specific_root_cause": rc["specific_root_cause"],
                                    "abstract_repair_logic": rc.get("abstract_repair_logic", ""),
                                    "effect": rc.get("effect", ""),
                                    "key_variable_lines": key_lines,
                                    "key_variables": rc.get("key_variables", [])
                                })

                        root_causes_with_variables = root_causes_with_variables[:num_root_causes_to_analyze]

                        if verbose:
                            print(f"Successfully identified {len(root_causes_with_variables)} root causes and their key variable line numbers")
                    else:
                        print(f"Warning: LLM did not return root causes in expected format (missing 'root_causes' list). Response: {response_text_root_cause}")
                except json.JSONDecodeError as je:
                    print(f"Warning: JSON decoding failed when parsing LLM root cause response: {je}. Response: {response_text_root_cause}")
            else:
                print(f"Warning: No JSON block found in LLM root cause response. Response: {response_text_root_cause}")
        else:
            print("Warning: LLM failed to generate root cause analysis.")

    except Exception as e:
        print(f"Error: Exception occurred while analyzing root causes - {e}")

    return root_causes_with_variables


def refine_root_cause_with_slice(
    vulnerable_code: str,
    cwe_id: str,
    initial_specific_root_cause: str,
    initial_abstract_repair_logic: str,
    initial_effect: str,
    key_variable_lines: List[int],
    model_config: dict,
    verbose: bool = False
) -> Optional[dict]:

    code_slice = ""
    try:
        code_slice, _ = slice_code_from_string(
            source_code=vulnerable_code,
            target_lines=key_variable_lines,
            slice_type="combined",
            data_flow_only=False,
            verbose=False
        )
        if not code_slice.strip():
            if verbose:
                print("Warning: Code slice generated based on key variables is empty. Using original code as fallback.")
            code_slice = vulnerable_code
        else:
            if verbose:
                print(f"Successfully generated code slice (based on line numbers: {key_variable_lines})")
    except Exception as e:
        if verbose:
            print(f"Error: Failed to generate code slice - {e}. Using original code as fallback.")
        code_slice = vulnerable_code

    code_slice_numbered = add_line_numbers_to_code(code_slice)

    formatted_key_variable_lines = format_lines_with_statements(vulnerable_code, key_variable_lines)

    prompt_refine_root_cause = f"""Based on the focused code slice extracted from the vulnerable code, refine and enhance the initial root cause analysis. Provide refined versions of the specific root cause, abstract repair logic, and expected effect.

CWE Type: {cwe_id}
Key Variable Lines:
{formatted_key_variable_lines}

Initial Analysis:
- Specific Root Cause: "{initial_specific_root_cause}"
- Abstract Repair Logic: "{initial_abstract_repair_logic}"
- Expected Effect: "{initial_effect}"

Focused Code Slice (extracted based on key variables):
```
{code_slice_numbered}
```

Task:
1. Analyze the focused code slice in detail
2. Refine all three aspects based on the specific code patterns and data flows visible in the slice
3. Provide more precise explanations with technical details from the code slice
4. Identify the exact source-to-sink flow that enables the vulnerability
5. Ensure the abstract repair logic remains generalizable while being more accurate

Output STRICTLY in the following JSON format:
```json
{{
  "specific_root_cause": "Refined and more precise description of the specific root cause, with concrete details from the code slice (variable names, line numbers, function calls)",
  "abstract_repair_logic": "Refined generalized repair strategy based on the code patterns observed, still without specific code details but more accurate",
  "effect": "Refined description of the expected outcome after repair, based on the specific vulnerability pattern observed",
  "source_sink_analysis": "Detailed explanation of the source-to-sink flow in the code slice",
  "triggering_conditions": "Specific conditions that must be met for the vulnerability to manifest",
  "confidence_level": "High|Medium|Low - confidence in this refined analysis"
}}
```

Focus on providing actionable insights that will help in finding similar vulnerability patterns and generating effective repairs.
"""

    try:
        api_call_params_refine = {
            "prompt": prompt_refine_root_cause,
            "model_config": model_config,
            "max_tokens": 4000,
            "temperature": DEFAULT_OPENAI_PARAMS.get("temperature", 0),
            "n": DEFAULT_OPENAI_PARAMS.get("n", 1)
        }
        response_text_refine_list = generate_with_OpenAI_model(**api_call_params_refine)

        if response_text_refine_list and response_text_refine_list[0]:
            response_text_refine = response_text_refine_list[0]

            json_match = re.search(r'```json\s*([\s\S]*?)\s*```', response_text_refine)
            if not json_match:
                json_match = re.search(r'({[\s\S]*})', response_text_refine)

            if json_match:
                json_str = json_match.group(1)
                try:
                    parsed_response = json.loads(json_str)
                    if "specific_root_cause" in parsed_response:
                        if verbose:
                            print(f"Successfully refined root cause description")
                            print(f"Confidence level: {parsed_response.get('confidence_level', 'N/A')}")

                        return {
                            "specific_root_cause": parsed_response["specific_root_cause"],
                            "abstract_repair_logic": parsed_response.get("abstract_repair_logic", initial_abstract_repair_logic),
                            "effect": parsed_response.get("effect", initial_effect),
                            "code_slice": code_slice,
                            "key_variable_lines": key_variable_lines,
                            "source_sink_analysis": parsed_response.get("source_sink_analysis", ""),
                            "triggering_conditions": parsed_response.get("triggering_conditions", ""),
                            "confidence_level": parsed_response.get("confidence_level", "Medium")
                        }
                    else:
                        print(f"Warning: LLM did not return refined root cause in expected format (missing 'specific_root_cause'). Response: {response_text_refine}")
                except json.JSONDecodeError as je:
                    print(f"Warning: JSON decoding failed when parsing LLM refined root cause response: {je}. Response: {response_text_refine}")
            else:
                print(f"Warning: No JSON block found in LLM refined root cause response. Response: {response_text_refine}")
        else:
            print("Warning: LLM failed to generate refined root cause analysis.")

    except Exception as e:
        print(f"Error: Exception occurred while refining root cause - {e}")

    if verbose:
        print("Failed to refine root cause, using original description as fallback")

    return {
        "specific_root_cause": initial_specific_root_cause,
        "abstract_repair_logic": initial_abstract_repair_logic,
        "effect": initial_effect,
        "code_slice": code_slice,
        "key_variable_lines": key_variable_lines,
        "source_sink_analysis": "Refinement failed, using original analysis",
        "triggering_conditions": "Refinement failed, using original analysis",
        "confidence_level": "Low"
    }


def select_best_repair_suggestion(
    suggestions: List[dict],
    original_code: str,
    model_config: dict,
    top_n: int = 1,
    graph_consistent: bool = False,
    verbose: bool = False
):
    if not suggestions:
        print("  No suggestions provided to select_best_repair_suggestion.")
        return None

    candidate_suggestions = []
    for i, s_item in enumerate(suggestions):
        patch = s_item.get("suggestion_patch")
        if not patch or not patch.strip():
            print(f"  Original suggestion {i+1} patch is empty, ignored (select_best_repair_suggestion).")
            continue

        candidate_suggestions.append(s_item)

    if not candidate_suggestions:
        print("  All repair suggestions are invalid (empty patch), cannot perform LLM evaluation (select_best_repair_suggestion).")
        return None

    def _evaluate_one_suggestion(s_item_param, original_code_param, idx_param):
        source_example_post_repair_state = s_item_param.get("source_example_post_repair_state")
        current_llm_score = 0.0

        if not source_example_post_repair_state or source_example_post_repair_state.lower() == "not available":
            print(f"      Warning: Candidate suggestion {idx_param+1} source_example_post_repair_state is invalid or missing. Cannot perform LLM evaluation, score is {current_llm_score} (select_best_repair_suggestion).")
        else:
            suggestion_patch = s_item_param.get("suggestion_patch")
            evaluation_prompt = f"""
You are a code analysis expert. Your task is to evaluate if a given 'Suggested Repair Patch' effectively transforms the 'Original Vulnerable Code' to a state that aligns with the 'Desired Post-Repair State Description'.

Original Vulnerable Code:
```
{original_code_param}
```

Suggested Repair Patch (Unified Diff Format):
```diff
{suggestion_patch}
```

Desired Post-Repair State Description (this describes the expected outcome for a similar vulnerability after repair, learn from it):
"{source_example_post_repair_state}"

Evaluation Task:
1. Carefully analyze the 'Original Vulnerable Code' and the 'Suggested Repair Patch' to understand the changes being made.
2. Assess if the 'Suggested Repair Patch', when applied to the 'Original Vulnerable Code', would achieve an outcome or program state that is consistent with the 'Desired Post-Repair State Description'.
3. Focus on whether the core functional or security objectives implied by the 'Desired Post-Repair State Description' are met by the 'Suggested Repair Patch'.

Output your assessment as a single word: 'true' if the 'Suggested Repair Patch' successfully achieves the state described by 'Desired Post-Repair State Description', or 'false' otherwise.
Do not provide any other explanation, preamble, or markdown formatting. Just the single word 'true' or 'false'.
"""
            try:

                eval_api_call_params = {
                    "prompt": evaluation_prompt,
                    "model_config": model_config,
                    "n": 1,
                    "max_tokens": 10,
                    "temperature": DEFAULT_OPENAI_PARAMS.get("temperature", 0)
                }
                llm_responses = generate_with_OpenAI_model(**eval_api_call_params)
                if llm_responses and llm_responses[0]:
                    response_text = llm_responses[0].strip().lower()
                    if response_text == "true":
                        current_llm_score = 1.0
                    elif response_text == "false":
                        pass
                    else:
                        print(f"      Warning: LLM evaluation for suggestion {idx_param+1} returned unclear result: '{llm_responses[0]}'. Score is {current_llm_score} (select_best_repair_suggestion).")
                else:
                    print(f"      Warning: LLM evaluation for suggestion {idx_param+1} did not return valid response. Score is {current_llm_score} (select_best_repair_suggestion).")
            except Exception as e:
                print(f"      Error: Exception occurred during LLM evaluation of suggestion {idx_param+1}: {e}. Score is {current_llm_score} (select_best_repair_suggestion).")

        return {
            "suggestion_item": s_item_param,
            "llm_score": current_llm_score,
            "original_idx": idx_param
        }

    evaluated_suggestions_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        futures = [
            executor.submit(_evaluate_one_suggestion, s_item, original_code, idx)
            for idx, s_item in enumerate(candidate_suggestions)
        ]
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    evaluated_suggestions_results.append(result)
            except Exception as exc:

                print(f"      Error: Unexpected error while processing a completed suggestion evaluation task: {exc}")

    evaluated_suggestions_results.sort(key=lambda x: x["original_idx"])
    evaluated_suggestions = [{"suggestion_item": r["suggestion_item"], "llm_score": r["llm_score"]} for r in evaluated_suggestions_results]

    if not evaluated_suggestions:
        print("  No suggestions were evaluated by LLM (select_best_repair_suggestion).")
        return None

    true_suggestions = [s for s in evaluated_suggestions if s["llm_score"] > 0]

    if not true_suggestions:
        print("  No repair suggestions passed LLM evaluation as 'true'. Failed to select best repair (select_best_repair_suggestion).")
        return None

    if graph_consistent and len(true_suggestions) > 1:

        if verbose:
            print("  Warning: Graph consistency analysis is temporarily unavailable due to removal of patch application step.")

        for s_eval_item in true_suggestions:
            s_eval_item['graph_consistency_group_id'] = 0

    def sort_key_func(x_eval_item):
        llm_score = x_eval_item.get("llm_score", 0.0)
        distance = float(x_eval_item["suggestion_item"].get("source_example_distance", float('inf')))
        return (-llm_score, distance)

    true_suggestions.sort(key=sort_key_func)

    if verbose:
        for idx_sorted, ts_item_sorted in enumerate(true_suggestions):
            dist_sorted = float(ts_item_sorted['suggestion_item'].get('source_example_distance', -1.0))
            print(f"    Sorted {idx_sorted+1}: LLM {ts_item_sorted.get('llm_score',0.0):.2f}, Dist {dist_sorted:.4f}")

    num_to_return = min(top_n, len(true_suggestions))
    selected_suggestions_details = true_suggestions[:num_to_return]

    final_suggestion_details = []

    if not selected_suggestions_details:
        print("  No qualified repair suggestions available for selection (select_best_repair_suggestion).")
        return None

    for i, s_detail in enumerate(selected_suggestions_details):
        suggestion_item = s_detail["suggestion_item"]
        llm_score = s_detail["llm_score"]

        display_distance = -1.0
        try:
            val = suggestion_item.get('source_example_distance', -1.0)
            if val is not None:
                display_distance = float(val)
        except (ValueError, TypeError):
            pass

        key_vars_preview = suggestion_item.get('key_variables', [])

        merged_suggestion_detail = suggestion_item.copy()
        merged_suggestion_detail['llm_score'] = llm_score
        merged_suggestion_detail['graph_consistency_group_id'] = s_detail.get('graph_consistency_group_id')
        final_suggestion_details.append(merged_suggestion_detail)

    if top_n == 1 and len(final_suggestion_details) == 1:
        print(f"  Final single repair suggestion selected (select_best_repair_suggestion).")
        return final_suggestion_details[0]
    elif not final_suggestion_details:

        print("  No final repair suggestion selected (select_best_repair_suggestion).")
        return None
    else:
        print(f"  Final {len(final_suggestion_details)} repair suggestions selected (select_best_repair_suggestion).")
        return final_suggestion_details


def _generate_single_repair_suggestion(
    vulnerable_code: str,
    cwe_id: str,
    vulnerable_line_numbers: List[int],
    code_slice: str,
    current_root_cause_desc: str,
    example: dict,
    model_config: dict,
    rc_idx: int,
    ex_idx: int,
    total_root_causes_for_display: int,
    num_examples_in_rc: int
) -> Optional[dict]:

    formatted_vulnerable_lines_approx = format_lines_with_statements(vulnerable_code, vulnerable_line_numbers)
    prompt_intro_individual = f"""
You are an expert code repair assistant. Your task is to repair the given vulnerable code based on an analysis of its specific root cause and by learning from the provided example of a similar vulnerability repair.

Original Vulnerable Code (CWE: {cwe_id}):
```
{add_line_numbers_to_code(vulnerable_code)}
```
Vulnerable Lines approx:
{formatted_vulnerable_lines_approx}

Focused Code Slice (key vulnerability-related context):
```
{code_slice if code_slice.strip() and code_slice != vulnerable_code else "No specific focused slice available or slice is same as full code; consider the full vulnerable code."}
```
---
"""
    prompt_current_root_cause_section = f"""
Identified Root Cause for this specific repair attempt:
- {current_root_cause_desc}
---
"""
    example_code_before = example.get('code_before', 'Not available')
    example_code_after = example.get('code_after_ground_truth', 'Not available')
    example_abstract_strategy = example.get('abstract_strategy', 'Not available')
    example_concrete_strategy = example.get('concrete_strategy', 'Not available')
    example_cwe_specific_strategy = example.get('cwe_specific_strategy', 'Not available')
    example_pre_repair_state = example.get('pre_repair_state_example', 'Not available')
    example_post_repair_state = example.get('post_repair_state_example', 'Not available')

    example_diff = '\n'.join(difflib.unified_diff(
        example_code_before.splitlines(keepends=True),
        example_code_after.splitlines(keepends=True),
        fromfile='example_vulnerable.c',
        tofile='example_fixed.c',
        lineterm=''
    ))
    prompt_current_example_section = f"""
Repair Example for Consideration:
  Pre-Repair State(root cause) described in Example: {example_pre_repair_state}
  Vulnerable Context (from example's code_before):
  ```
{add_line_numbers_to_code(example_code_before) if example_code_before != 'Not available' else example_code_before}
  ```
  Repair Patch (Unified Diff Format showing the exact changes made):
  ```
{example_diff}
  ```
"""
    if example_abstract_strategy != 'Not available' and example_abstract_strategy:
        prompt_current_example_section += f"  Abstract Repair Strategy (from example):\n  {example_abstract_strategy}\n"
    if example_concrete_strategy != 'Not available' and example_concrete_strategy:
        prompt_current_example_section += f"  Concrete Repair Strategy (from example):\n  {example_concrete_strategy}\n"
    if example_cwe_specific_strategy != 'Not available' and example_cwe_specific_strategy:
        prompt_current_example_section += f"  CWE-Specific Repair Strategy (from example):\n  {example_cwe_specific_strategy}\n"
    prompt_current_example_section += "---\n"

    prompt_instruction_individual = f"""

Based on the 'Identified Root Cause for this specific repair attempt' and by learning from the provided 'Repair Example' (its strategies and code edits), generate a unified diff patch to repair the vulnerability in the 'Original Vulnerable Code' shown at the beginning.
The repair should aim to address the identified root cause as effectively as possible, drawing inspiration from the example if it helps.

Output Format:
Please provide your response in the following structured format (NOT JSON):

REPAIR_STRATEGY_START:
[A concise description of the repair approach taken]
REPAIR_STRATEGY_END:

KEY_VARIABLES_START:
[List key variables, functions, or crucial program elements, separated by commas]
KEY_VARIABLES_END:

VULNERABILITY_ANALYSIS_START:
[A brief explanation of what vulnerability was identified and how it's fixed]
VULNERABILITY_ANALYSIS_END:

PATCH_DIFF_START:
[Your unified diff patch here - this should be in standard unified diff format showing exactly what lines to change]
PATCH_DIFF_END:

**Important:**
- Generate a valid unified diff that can be applied with standard patch tools
- Focus on the minimal changes needed to fix the security issue based on the root cause
- Ensure the patch maintains original functionality while addressing the vulnerability
- Do not include any other explanations or formatting around the structured response
- The patch should be immediately applicable to the provided code
- Address the specific root cause: {current_root_cause_desc}...
"""
    individual_repair_prompt = (
        prompt_intro_individual +
        prompt_current_root_cause_section +
        prompt_current_example_section +
        prompt_instruction_individual
    )

    try:

        api_call_params_repair = {
            "prompt": individual_repair_prompt,
            "model_config": model_config,
            "max_tokens": 16000,
            "temperature": model_config.get("temperature", DEFAULT_OPENAI_PARAMS.get("temperature", 0)),
            "n": model_config.get("n", DEFAULT_OPENAI_PARAMS.get("n", 1))
        }
        response_text_repair_list = generate_with_OpenAI_model(**api_call_params_repair)

        if response_text_repair_list and response_text_repair_list[0]:
            generated_response_text = response_text_repair_list[0].strip()

            try:

                patch_diff = None
                repair_strategy = None
                key_variables = []

                patch_match = re.search(r'PATCH_DIFF_START:\s*(.*?)\s*PATCH_DIFF_END:', generated_response_text, re.DOTALL)
                if patch_match:
                    patch_diff = patch_match.group(1).strip()

                strategy_match = re.search(r'REPAIR_STRATEGY_START:\s*(.*?)\s*REPAIR_STRATEGY_END:', generated_response_text, re.DOTALL)
                if strategy_match:
                    repair_strategy = strategy_match.group(1).strip()

                variables_match = re.search(r'KEY_VARIABLES_START:\s*(.*?)\s*KEY_VARIABLES_END:', generated_response_text, re.DOTALL)
                if variables_match:
                    variables_text = variables_match.group(1).strip()
                    if variables_text:

                        key_variables = [var.strip() for var in variables_text.split(',') if var.strip()]

                if not patch_diff or not patch_diff.strip():
                    print(f"      LLM response 'patch_diff' is missing or empty for RC {rc_idx+1}, Ex {ex_idx+1}. Response: '{generated_response_text[:200]}...'")
                    return None
                if not repair_strategy or not repair_strategy.strip():
                    print(f"      LLM response 'repair_strategy' is missing or empty for RC {rc_idx+1}, Ex {ex_idx+1}. Response: '{generated_response_text[:200]}...'")
                    return None

                current_example_distance = -1.0
                try:
                    val = example.get("distance", -1.0)
                    if val is not None:
                        current_example_distance = float(val)
                except (ValueError, TypeError):
                    pass

                return {
                    "suggestion_patch": patch_diff,
                    "repair_strategy": repair_strategy,
                    "key_variables": key_variables,
                    "source_root_cause_desc": current_root_cause_desc,
                    "source_example_pre_repair_state": example_pre_repair_state,
                    "source_example_post_repair_state": example_post_repair_state,
                    "source_example_code_before": example_code_before,
                    "source_example_code_after": example_code_after,
                    "source_example_distance": current_example_distance
                }

            except Exception as e:
                print(f"      Unexpected error processing LLM response for RC {rc_idx+1}, Ex {ex_idx+1}: {e}. Response: '{generated_response_text[:200]}...'")
                return None

        else:
            print(f"      LLM call did not return a valid response for repair (RC {rc_idx+1}, Ex {ex_idx+1}).")
            return None
    except Exception as e:
        print(f"      Error: Calling LLM for root cause {rc_idx+1}, example {ex_idx+1} exception occurred while generating repair code - {e}")
        return None


def generate_vulnerability_repair(
    vulnerable_code: str,
    cwe_id: str,
    vulnerable_line_numbers: List[int],
    generation_model_config: dict,
    evaluation_model_config: dict,
    num_root_causes_to_analyze: int = 3,
    num_examples_per_cause: int = 2,
    top_n: int = 3,
    graph_consistent: bool = False,
    verbose_graph: bool = False,
    enable_root_cause_filtering: bool = True,
    min_consistency_level: str = "Medium",
    min_confidence_score: float = 0.6,
    enable_direct_llm_fallback: bool = True,
    enable_patch_grouping: bool = False
):

    initial_root_causes_with_variables = identify_root_causes_and_key_variables(
        vulnerable_code=vulnerable_code,
        cwe_id=cwe_id,
        vulnerable_line_numbers=vulnerable_line_numbers,
        model_config=generation_model_config,
        num_root_causes_to_analyze=num_root_causes_to_analyze,
        verbose=verbose_graph
    )

    if not initial_root_causes_with_variables:
        print("Failed to analyze root cause, cannot continue repair.")
        return None

    refined_root_causes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        future_to_rc_data_desc = {}
        for rc_data in initial_root_causes_with_variables:
            future = executor.submit(refine_root_cause_with_slice,
                                     vulnerable_code=vulnerable_code,
                                     cwe_id=cwe_id,
                                     initial_specific_root_cause=rc_data["specific_root_cause"],
                                     initial_abstract_repair_logic=rc_data.get("abstract_repair_logic", ""),
                                     initial_effect=rc_data.get("effect", ""),
                                     key_variable_lines=rc_data["key_variable_lines"],
                                     model_config=generation_model_config,
                                     verbose=verbose_graph)
            future_to_rc_data_desc[future] = rc_data.get("specific_root_cause", "UnknownRootCause")

        for future in concurrent.futures.as_completed(future_to_rc_data_desc):
            rc_description_for_error = future_to_rc_data_desc[future]
            try:
                refined_rc = future.result()
                if refined_rc:
                    refined_root_causes.append(refined_rc)
            except Exception as exc:
                print(f"      Error refining root cause '{rc_description_for_error[:50]}...': {exc}")

    if not refined_root_causes:
        print("Failed to generate precise root cause description, cannot continue repair.")
        return None

    root_causes_with_examples = []

    for i, refined_rc_data in enumerate(refined_root_causes):
        current_cause_data = {
            "root_cause": refined_rc_data["specific_root_cause"],
            "abstract_repair_logic": refined_rc_data.get("abstract_repair_logic", ""),
            "effect": refined_rc_data.get("effect", ""),
            "code_slice": refined_rc_data["code_slice"],
            "key_variable_lines": refined_rc_data["key_variable_lines"],
            "examples": []
        }

        cwe_processor, vector_querier = get_thread_local_instances()

        try:
            _, processed_top_parent = cwe_processor.process_cwe(cwe_id)
            if processed_top_parent not in MAIN_CWE_TYPES_FOR_INDEXING:
                query_cwe_type = "CWE-0"
            else:
                query_cwe_type = processed_top_parent
        except Exception as e:
            print(f"    Error: Failed to get CWE parent type for {cwe_id} - {e}. Will try to use original CWE ID.")
            query_cwe_type = cwe_id

        try:
            similar_examples = vector_querier.search(
                query_text=refined_rc_data["specific_root_cause"],
                top_k=num_examples_per_cause,
                cwe_type=query_cwe_type
            )
            if similar_examples:

                initial_examples = []
                for ex_idx, example in enumerate(similar_examples):
                    metadata = example.get("metadata", {})
                    example_data = {
                        "code_before": metadata.get("code_before"),
                        "code_after_ground_truth": metadata.get("code_after_ground_truth"),
                        "abstract_strategy": metadata.get("final_llm1_abstract_strategy"),
                        "concrete_strategy": metadata.get("final_llm1_concrete_strategy"),
                        "cwe_specific_strategy": metadata.get("final_llm1_cwe_specific_strategy"),
                        "pre_repair_state_example": metadata.get("final_llm1_pre_repair_state", "Not available"),
                        "post_repair_state_example": metadata.get("final_llm1_post_repair_state", "Not available"),
                        "distance": example.get("distance")
                    }
                    if example_data["code_before"] and example_data["code_after_ground_truth"]:
                        initial_examples.append(example_data)

                    else:
                        print(f"      Warning: Example {ex_idx+1} metadata incomplete (missing code_before or code_after_ground_truth)，skipped.")

                if enable_root_cause_filtering and initial_examples:

                    consistency_level_enum = RootCauseConsistency.MEDIUM
                    try:
                        if min_consistency_level.lower() == "high":
                            consistency_level_enum = RootCauseConsistency.HIGH
                        elif min_consistency_level.lower() == "medium":
                            consistency_level_enum = RootCauseConsistency.MEDIUM
                        elif min_consistency_level.lower() == "low":
                            consistency_level_enum = RootCauseConsistency.LOW
                        else:
                            print(f"    Warning: Unknown consistency level '{min_consistency_level}', using default value MEDIUM")
                    except Exception as enum_e:
                        print(f"    Warning: Error occurred while converting consistency level: {enum_e}, using default value MEDIUM")

                    filtered_examples = filter_examples_by_root_cause_consistency(
                        current_root_cause=refined_rc_data["specific_root_cause"],
                        examples=initial_examples,
                        cwe_id=cwe_id,
                        model_config=evaluation_model_config,
                        min_consistency_level=consistency_level_enum,
                        min_confidence_score=min_confidence_score,
                        verbose=verbose_graph
                    )

                    if filtered_examples:
                        current_cause_data["examples"] = filtered_examples
                        if verbose_graph:
                            print(f"    Root Cause consistency filtering: retained {len(filtered_examples)}/{len(initial_examples)}  examples")
                    else:

                        print(f"    Root Cause consistency filtering: All examples do not meet requirements (level: {min_consistency_level}, confidence: {min_confidence_score}), this root cause will skip example-based repair")
                        current_cause_data["examples"] = []
                else:

                    current_cause_data["examples"] = initial_examples
                    if enable_root_cause_filtering:
                        print(f"    Root Cause consistency filtering: skip (no valid initial examples)")
                    else:
                        print(f"    Root Cause consistency filtering: disabled, directly using {len(initial_examples)}  examples")
            else:
                print(f"    Warning: Failed for root cause '{refined_rc_data['specific_root_cause'][:50]}...' find similar examples (CWE type: {query_cwe_type})。")
        except Exception as e:
            print(f"    Error: Exception occurred during Faiss query - {e}")

        root_causes_with_examples.append(current_cause_data)

    has_any_examples = any(rc_data["examples"] for rc_data in root_causes_with_examples)

    if enable_root_cause_filtering:
        total_root_causes = len(root_causes_with_examples)
        root_causes_with_examples_count = sum(1 for rc_data in root_causes_with_examples if rc_data["examples"])
        root_causes_without_examples_count = total_root_causes - root_causes_with_examples_count

        if verbose_graph:
            print(f"Root Cause consistency filtering statistics:")
            print(f"  Total root causes: {total_root_causes}")
            print(f"  Root causes with available examples: {root_causes_with_examples_count}")
            print(f"  Root causes without available examples: {root_causes_without_examples_count}")

        if root_causes_without_examples_count > 0:
            print(f"Note: {root_causes_without_examples_count}/{total_root_causes} root causes have no available examples after consistency filtering")

    all_repair_suggestions = []

    if not refined_root_causes:
        print("Warning: No root cause analyzed, cannot continue generating repair suggestions.")

    has_any_examples = any(rc_data.get("examples") for rc_data in root_causes_with_examples)
    if not has_any_examples and refined_root_causes:
        if enable_root_cause_filtering:
            print("Warning: All root causes have no available examples after consistency filtering. Will rely on direct LLM repair method.")
        else:
            print("Warning: Root causes exist, but none have related repair examples. Repair process may not be example-based.")

    if refined_root_causes:
        total_root_causes_for_display = len(refined_root_causes)
    elif root_causes_with_examples:
        total_root_causes_for_display = len(root_causes_with_examples)
    else:
        total_root_causes_for_display = 0
        print("Warning: 'refined_root_causes' and 'root_causes_with_examples' are both empty or undefined, cannot determine total root causes.")

    futures = []

    cpu_cores = multiprocessing.cpu_count()
    max_workers = 64

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for rc_idx, rc_data in enumerate(root_causes_with_examples):
            current_root_cause_desc = rc_data.get("root_cause")
            current_code_slice = rc_data.get("code_slice")
            if not current_root_cause_desc:
                print(f"  Warning: Root cause entry {rc_idx+1} description missing, skipping repair task submission.")
                continue

            examples_for_rc = rc_data.get("examples")
            if not examples_for_rc:
                print(f"  root cause '{current_root_cause_desc[:50]}...' has no examples, skipping repair task submission for this root cause.")
                continue

            for ex_idx, example_item in enumerate(examples_for_rc):
                future = executor.submit(
                    _generate_single_repair_suggestion,
                    vulnerable_code,
                    cwe_id,
                    vulnerable_line_numbers,
                    current_code_slice,
                    current_root_cause_desc,
                    example_item,
                    generation_model_config,
                    rc_idx,
                    ex_idx,
                    total_root_causes_for_display,
                    len(examples_for_rc)
                )
                futures.append(future)

    for i, future in enumerate(concurrent.futures.as_completed(futures)):
        try:

            result = future.result()
            if result:
                all_repair_suggestions.append(result)

        except Exception as e:

            print(f"  Error: Processing a completed repair suggestion task {i+1}/{len(futures)} unexpected error occurred: {e}")

    direct_llm_suggestions = []
    if enable_direct_llm_fallback and refined_root_causes:
        if verbose_graph:
            print(f"  For {len(refined_root_causes)} refined root causes, attempting direct LLM repair...")
        if isinstance(refined_root_causes, list):
            for rc_idx_direct, rc_data in enumerate(refined_root_causes):
                if not isinstance(rc_data, dict):
                    if verbose_graph:
                        print(f"    Warning: Element in refined_root_causes (index {rc_idx_direct}) is not a dictionary, skipping. Element: {rc_data}")
                    continue

                current_specific_root_cause = rc_data.get("specific_root_cause")
                current_code_slice_for_rc = rc_data.get("code_slice")

                if not current_code_slice_for_rc or not current_code_slice_for_rc.strip():
                    current_code_slice_for_rc = vulnerable_code
                    if verbose_graph:
                        print(f"    Warning: root cause '{str(current_specific_root_cause)[:50]}...' 's code_slice is empty, using complete code.")

                vulnerable_line_numbers_for_rc = rc_data.get("key_variable_lines", vulnerable_line_numbers)

                if not current_specific_root_cause:
                    if verbose_graph:
                        print(f"    Warning: Refined root cause description missing (index {rc_idx_direct}), skipping direct LLM repair.")
                    continue

                if verbose_graph:
                    print(f"    Forroot cause '{str(current_specific_root_cause)[:50]}...' (index {rc_idx_direct}) Generating direct LLM repair...")

                individual_direct_suggestions = generate_simple_vulnerability_repair_from_root_causes(
                    vulnerable_code=vulnerable_code,
                    cwe_id=cwe_id,
                    vulnerable_line_numbers=vulnerable_line_numbers_for_rc,
                    code_slice=current_code_slice_for_rc,
                    root_causes=[current_specific_root_cause],
                    model_config=generation_model_config,
                    top_n=1,
                    verbose=verbose_graph
                )
                if individual_direct_suggestions:
                    direct_llm_suggestions.extend(individual_direct_suggestions)
                    if verbose_graph:
                        print(f"      Successfully for root cause '{str(current_specific_root_cause)[:50]}...' generated {len(individual_direct_suggestions)} direct LLM suggestions.")
                elif verbose_graph:
                    print(f"      Failed for root cause '{str(current_specific_root_cause)[:50]}...' generate direct LLM suggestions.")
        else:
            if verbose_graph:
                print(f"    Warning: refined_root_causes is not a list (type: {type(refined_root_causes)}), cannot perform direct LLM repair.")

        if direct_llm_suggestions:
            if verbose_graph:
                print(f"  Total generated {len(direct_llm_suggestions)} direct LLM repair suggestions. Will merge with example-based suggestions.")
            all_repair_suggestions.extend(direct_llm_suggestions)
        elif verbose_graph and refined_root_causes and isinstance(refined_root_causes, list) and len(refined_root_causes) > 0:
            print(f"  Failed to generate any direct LLM repair suggestions (when enable_direct_llm_fallback=True and refined root causes exist)。")

    if enable_patch_grouping and all_repair_suggestions:
        if verbose_graph:
            print(f"Applying patch grouping enhancement algorithm to {len(all_repair_suggestions)} repair suggestions...")

        enhanced_suggestions = apply_patch_grouping_enhancement(
            repair_suggestions=all_repair_suggestions,
            vulnerable_code=vulnerable_code,
            cwe_id=cwe_id,
            vulnerable_line_numbers=vulnerable_line_numbers,
            model_config=generation_model_config,
            enable_patch_grouping=True,
            config=None,
            verbose=verbose_graph
        )

        if enhanced_suggestions != all_repair_suggestions:
            if verbose_graph:
                print(f"Patch grouping enhancement completed: {len(enhanced_suggestions)} suggestions (contains enhanced patch)")
            all_repair_suggestions = enhanced_suggestions
        else:
            if verbose_graph:
                print("Patch grouping enhancement did not produce new suggestions")

    final_repaired_suggestions = None
    if all_repair_suggestions:
        final_repaired_suggestions = select_best_repair_suggestion(
            all_repair_suggestions,
            vulnerable_code,
            model_config=evaluation_model_config,
            top_n=top_n,
            graph_consistent=graph_consistent,
            verbose=verbose_graph
        )

        if final_repaired_suggestions is None:
            print("  Failed to select final repair object from LLM suggestions.")

            print("  Failed to select final repair object from merged suggestions.")
            return []

        suggestions_to_process = []

        if isinstance(final_repaired_suggestions, dict):
            suggestions_to_process = [final_repaired_suggestions]
        elif isinstance(final_repaired_suggestions, list):
            suggestions_to_process = final_repaired_suggestions
        else:
            print(f"  Unknown return type ({type(final_repaired_suggestions)}) from select_best_repair_suggestion.")
            return None

        valid_suggestions_found = False
        for i, sugg_obj in enumerate(suggestions_to_process):
            if sugg_obj and isinstance(sugg_obj, dict) and sugg_obj.get("suggestion_patch"):
                valid_suggestions_found = True

                strategy = sugg_obj.get("repair_strategy", "N/A")
                key_vars = sugg_obj.get("key_variables", [])
                llm_s = sugg_obj.get("llm_score", "N/A")
                gid = sugg_obj.get("graph_consistency_group_id", "N/A")
                repair_method = sugg_obj.get("repair_method", "example_based")

                if verbose_graph:
                    print(f"\n  --- Final selected suggestion {i+1} details ---")
                    print(f"    Repair method: {repair_method}")
                    print(f"    Repair strategy: {strategy}")
                    print(f"    Key variables: {key_vars}")
                    print(f"    LLM score: {llm_s}, Graph group ID: {gid}")
                    if repair_method == "enhanced_group":
                        print(f"    Enhanced group ID: {sugg_obj.get('group_id', 'N/A')}")
                        print(f"    Original patch count: {sugg_obj.get('original_patches_count', 'N/A')}")
            else:
                print(f"    Warning: Suggestion object {i+1} structure incomplete or missing 'suggestion_patch'.")

        if not valid_suggestions_found:
            print("  Although select_best_repair_suggestion returned an object, failed to confirm any valid suggestions containing repair patches.")
            return []

        return suggestions_to_process
    else:
        print("  No repair suggestions generated, cannot select.")

        print("  After all stages (example-based and direct LLM), no repair suggestions generated.")
        return []


def generate_simple_vulnerability_repair_from_root_causes(
    vulnerable_code: str,
    cwe_id: str,
    vulnerable_line_numbers: List[int],
    code_slice: str,
    root_causes: List[str],
    model_config: dict,
    top_n: int = 1,
    verbose: bool = False
) -> List[dict]:

    def _generate_for_one_root_cause(rc_idx_param: int, root_cause_desc_param: str) -> Optional[dict]:
        formatted_vulnerable_lines = format_lines_with_statements(vulnerable_code, vulnerable_line_numbers)

        repair_prompt = f"""
You are an expert security code analyst and vulnerability repair specialist. Your task is to analyze the given vulnerable code and generate a precise patch to fix the identified security vulnerability.

**Vulnerable Code (CWE: {cwe_id}):**
```c
{add_line_numbers_to_code(vulnerable_code)}
```

**Vulnerable Lines:**
{formatted_vulnerable_lines}

**Focused Code Slice (key vulnerability-related context):**
```c
{code_slice if code_slice.strip() and code_slice != vulnerable_code else "No specific focused slice available or slice is same as full code; consider the full vulnerable code."}
```

**Identified Root Cause:**
{root_cause_desc_param}

**Task:**
1. Carefully analyze the provided vulnerable code, paying special attention to the lines marked as vulnerable.
2. Consider the focused code slice which highlights the key vulnerability-related context.
3. Consider the identified root cause to understand the specific security vulnerability.
4. Design a minimal but effective fix that:
   - Addresses the specific root cause identified
   - Eliminates the security vulnerability
   - Preserves the original code functionality
   - Follows secure coding best practices
   - Makes the smallest necessary changes

**Output Requirements:**
Please provide your response in the following structured format (NOT JSON):

REPAIR_STRATEGY_START:
[A concise description of the repair approach taken]
REPAIR_STRATEGY_END:

KEY_VARIABLES_START:
[List key variables, functions, or crucial program elements, separated by commas]
KEY_VARIABLES_END:

VULNERABILITY_ANALYSIS_START:
[A brief explanation of what vulnerability was identified and how it's fixed]
VULNERABILITY_ANALYSIS_END:

PATCH_DIFF_START:
[Your unified diff patch here - this should be in standard unified diff format showing exactly what lines to change]
PATCH_DIFF_END:

**Important:**
- Generate a valid unified diff that can be applied with standard patch tools
- Focus on the minimal changes needed to fix the security issue based on the root cause
- Ensure the patch maintains original functionality while addressing the vulnerability
- Do not include any other explanations or formatting around the structured response
- The patch should be immediately applicable to the provided code
- Address the specific root cause above
"""
        try:
            if verbose:
                print(f"    Calling LLM to generate based on root cause {rc_idx_param+1} 's repair patch...")

            api_call_params = {
                "prompt": repair_prompt,
                "model_config": model_config,
                "max_tokens": 16000,
                "temperature": DEFAULT_OPENAI_PARAMS.get("temperature", 0),
                "n": DEFAULT_OPENAI_PARAMS.get("n", 1)
            }
            responses = generate_with_OpenAI_model(**api_call_params)

            if not responses or not responses[0]:
                if verbose:
                    print(f"    Error: LLM did not return valid response (root cause {rc_idx_param+1})")
                return None
            response_text = responses[0].strip()

            patch_diff = None
            repair_strategy = None
            key_variables = []
            vulnerability_analysis = None

            patch_match = re.search(r'PATCH_DIFF_START:\s*(.*?)\s*PATCH_DIFF_END:', response_text, re.DOTALL)
            if patch_match:
                patch_diff = patch_match.group(1).strip()
            strategy_match = re.search(r'REPAIR_STRATEGY_START:\s*(.*?)\s*REPAIR_STRATEGY_END:', response_text, re.DOTALL)
            if strategy_match:
                repair_strategy = strategy_match.group(1).strip()
            variables_match = re.search(r'KEY_VARIABLES_START:\s*(.*?)\s*KEY_VARIABLES_END:', response_text, re.DOTALL)
            if variables_match:
                variables_text = variables_match.group(1).strip()
                if variables_text:
                    key_variables = [var.strip() for var in variables_text.split(',') if var.strip()]
            analysis_match = re.search(r'VULNERABILITY_ANALYSIS_START:\s*(.*?)\s*VULNERABILITY_ANALYSIS_END:', response_text, re.DOTALL)
            if analysis_match:
                vulnerability_analysis = analysis_match.group(1).strip()

            if not patch_diff or not patch_diff.strip():
                if verbose:
                    print(f"    Error: patch_difffield is empty (root cause {rc_idx_param+1})")
                return None
            if not repair_strategy or not repair_strategy.strip():
                if verbose:
                    print(f"    Error: repair_strategyfield is empty (root cause {rc_idx_param+1})")
                return None
            if not vulnerability_analysis or not vulnerability_analysis.strip():
                if verbose:
                    print(f"    Error: vulnerability_analysisfield is empty (root cause {rc_idx_param+1})")
                return None

            repair_suggestion = {
                "suggestion_patch": patch_diff,
                "repair_strategy": repair_strategy,
                "key_variables": key_variables,
                "source_root_cause_desc": root_cause_desc_param,
                "source_example_pre_repair_state": "Direct LLM repair - no example used",
                "source_example_post_repair_state": vulnerability_analysis,
                "source_example_code_before": "N/A",
                "source_example_code_after": "N/A",
                "source_example_distance": 999.0,
                "llm_score": 1.0,
                "repair_method": "direct_llm"
            }
            if verbose:
                print(f"    Successfully generated based on root cause {rc_idx_param+1} 's repair patch")

            return repair_suggestion
        except Exception as e:
            if verbose:
                print(f"    Error: Failed to parse or process response (root cause {rc_idx_param+1}) - {e}")
                if 'response_text' in locals():
                    print(f"    Response content: {response_text[:500]}...")
            return None

    collected_suggestions_with_idx = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        future_to_idx = {
            executor.submit(_generate_for_one_root_cause, rc_idx, root_cause_desc): rc_idx
            for rc_idx, root_cause_desc in enumerate(root_causes)
        }
        for future in concurrent.futures.as_completed(future_to_idx):
            original_rc_idx = future_to_idx[future]
            try:
                suggestion = future.result()
                if suggestion:
                    collected_suggestions_with_idx.append((original_rc_idx, suggestion))
            except Exception as exc:
                if verbose:
                    print(f"    Error: Exception occurred while generating direct LLM repair (root cause index {original_rc_idx}): {exc}")

    collected_suggestions_with_idx.sort(key=lambda x: x[0])
    repair_suggestions = [item[1] for item in collected_suggestions_with_idx]

    if repair_suggestions:
        if verbose:
            print(f"Successfully generated {len(repair_suggestions)} direct LLM repair suggestions based on root cause")
        return repair_suggestions[:top_n]
    else:
        if verbose:
            print("Failed to generate any direct LLM repair suggestions based on root cause")
        return []


def find_insertion_point(original_code: str, fixed_code: str) -> Optional[List[int]]:
    if not original_code.strip() and fixed_code.strip():
        return [1]

    original_lines = original_code.splitlines()
    fixed_lines = fixed_code.splitlines()

    matcher = difflib.SequenceMatcher(None, original_lines, fixed_lines)
    opcodes = matcher.get_opcodes()

    context_lines = []

    for tag, i1, i2, j1, j2 in opcodes:

        if tag == 'insert' or (tag == 'replace' and i1 == i2):

            current_op_context = []
            if i1 == 0:
                if len(original_lines) > 0:
                    current_op_context.append(1)

            elif i1 == len(original_lines):
                if len(original_lines) > 0:
                    current_op_context.append(len(original_lines))
            else:

                current_op_context.append(i1)
                current_op_context.append(i1 + 1)

            if current_op_context:
                context_lines.extend(current_op_context)

                break

    if context_lines:
        return sorted(list(set(context_lines)))

    return None


def _process_row_and_write_result(
    row_idx: int,
    original_code: Optional[str],
    fixed_code: Optional[str],
    cwe_id: Optional[str],
    trigger_path_value: Optional[str],

    num_root_causes_to_analyze: int,
    num_examples_per_cause: int,
    top_n_suggestions: int,
    graph_consistent: bool,
    verbose_graph: bool,
    enable_llm_evaluation: bool,

    generation_model_config: dict,
    evaluation_model_config: dict,
    enable_root_cause_filtering: bool,
    min_consistency_level: str,
    min_confidence_score: float,
    enable_direct_llm_fallback: bool,
    enable_patch_grouping: bool,

    output_json_path: str
):
    current_entry_identifier = f"CSV Row {row_idx + 2} (CWE: {cwe_id or 'N/A'}) (Thread: {threading.get_ident()})"

    result_entry = {
        "csv_row": row_idx + 2,
        "original_code": original_code,
        "fixed_code": fixed_code,
        "cwe_id": cwe_id,
        "vulnerable_lines": [],
        "line_source_method": None
    }

    if not all([original_code, fixed_code, cwe_id]):
        error_msg = "Missing one or more required fields (code_before, code_after, cwe_id)."
        print(f"  Skipping {current_entry_identifier}: {error_msg}")
        result_entry.update({
            "status": "error",
            "error_message": error_msg
        })
    else:
        vulnerable_line_numbers: List[int] = []
        line_source_method: Optional[str] = None
        skip_processing_flag: bool = False

        if trigger_path_value and trigger_path_value.strip() and trigger_path_value.strip() != "?":
            try:
                parsed_lines = json.loads(trigger_path_value)
                if isinstance(parsed_lines, list) and all(isinstance(line, int) for line in parsed_lines):
                    if parsed_lines:
                        vulnerable_line_numbers = parsed_lines
                        line_source_method = "trigger_path"
                    else:
                        print(f"  {current_entry_identifier}: trigger_path provided empty list, falling back to analyze_code_diff.")
                else:
                    print(f"  {current_entry_identifier}: trigger_path ('{trigger_path_value}') not a valid int list, falling back to analyze_code_diff.")
            except json.JSONDecodeError:
                print(f"  {current_entry_identifier}: trigger_path ('{trigger_path_value}') JSON parse failed, falling back to analyze_code_diff.")

        if not vulnerable_line_numbers:
            if line_source_method is None:
                print(f"  {current_entry_identifier}: No valid lines from trigger_path, attempting analyze_code_diff...")
            try:
                diff_lines, _ = analyze_code_diff(original_code, fixed_code)
                if diff_lines:
                    vulnerable_line_numbers = diff_lines
                    line_source_method = "analyze_code_diff"
                else:
                    if verbose_graph:
                        print(f"  {current_entry_identifier}: analyze_code_diff did not return lines, attempting find_insertion_point...")

                    insertion_points = None
                    if original_code is not None and fixed_code is not None:
                        insertion_points = find_insertion_point(original_code, fixed_code)

                    if insertion_points:
                        vulnerable_line_numbers = insertion_points
                        line_source_method = "diff_insertion_point"
                        if verbose_graph:
                            print(f"  {current_entry_identifier}: Using line numbers from find_insertion_point: {vulnerable_line_numbers}")
                    else:
                        error_msg = "No vulnerable lines found from trigger_path, analyze_code_diff, or find_insertion_point."
                        print(f"  {current_entry_identifier}: {error_msg} Skipping repair.")
                        result_entry.update({"status": "skipped_no_line_numbers", "message": error_msg, "vulnerable_lines": []})
                        skip_processing_flag = True
            except Exception as diff_e:
                error_msg = f"Failed to analyze code diff or find insertion point: {str(diff_e)}"
                print(f"  Error for {current_entry_identifier}: {error_msg}")
                result_entry.update({"status": "error_diff_analysis", "error_message": error_msg, "vulnerable_lines": []})
                skip_processing_flag = True

        if not skip_processing_flag:

            result_entry["vulnerable_lines"] = vulnerable_line_numbers
            result_entry["line_source_method"] = line_source_method

        if not skip_processing_flag:

            try:
                repair_suggestions_details = generate_vulnerability_repair(
                    vulnerable_code=original_code,
                    cwe_id=cwe_id,
                    vulnerable_line_numbers=vulnerable_line_numbers,
                    generation_model_config=generation_model_config,
                    evaluation_model_config=evaluation_model_config,
                    num_root_causes_to_analyze=num_root_causes_to_analyze,
                    num_examples_per_cause=num_examples_per_cause,
                    top_n=top_n_suggestions,
                    graph_consistent=graph_consistent,
                    verbose_graph=verbose_graph,
                    enable_root_cause_filtering=enable_root_cause_filtering,
                    min_consistency_level=min_consistency_level,
                    min_confidence_score=min_confidence_score,
                    enable_direct_llm_fallback=enable_direct_llm_fallback,
                    enable_patch_grouping=enable_patch_grouping
                )

                if repair_suggestions_details:

                    evaluations = []
                    eval_stats = {}
                    ground_truth_diff = ""

                    if enable_llm_evaluation:

                        ground_truth_diff = '\n'.join(difflib.unified_diff(
                            original_code.splitlines(keepends=True),
                            fixed_code.splitlines(keepends=True),
                            fromfile='original_vulnerable.c',
                            tofile='ground_truth_fixed.c',
                            lineterm=''
                        ))

                        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
                            future_to_suggestion_idx = {}
                            for i, repair_suggestion_item in enumerate(repair_suggestions_details):
                                if isinstance(repair_suggestion_item, dict):
                                    suggestion_patch = repair_suggestion_item.get('suggestion_patch', '')
                                    if suggestion_patch:
                                        future = executor.submit(evaluate_patch_quality,
                                                                 original_vulnerable_code=original_code,
                                                                 generated_patch=suggestion_patch,
                                                                 ground_truth_patch=ground_truth_diff,
                                                                 cwe_id=cwe_id,


                                                                 model_config=evaluation_model_config,
                                                                 verbose=verbose_graph)
                                        future_to_suggestion_idx[future] = (i, repair_suggestion_item, suggestion_patch)
                                    else:
                                        print(f"    Warning: suggestion {i+1} has no valid patch, skipping evaluation submission")
                                        evaluations.append({
                                            "suggestion_index": i, "evaluation_result": "Skipped_NoPatch",
                                            "explanation": "Patch was empty", "evaluation_details": {},
                                            "generated_patch": "", "original_suggestion_metadata": repair_suggestion_item
                                        })
                                else:
                                    print(f"    Warning: suggestion {i+1} format incorrect, skipping evaluation submission")
                                    evaluations.append({
                                        "suggestion_index": i, "evaluation_result": "Skipped_BadFormat",
                                        "explanation": "Suggestion format incorrect", "evaluation_details": {},
                                        "generated_patch": "", "original_suggestion_metadata": repair_suggestion_item
                                    })

                            temp_evaluations = {}
                            for future in concurrent.futures.as_completed(future_to_suggestion_idx):
                                original_idx, original_suggestion, patch_used = future_to_suggestion_idx[future]
                                try:
                                    eval_result, explanation, eval_data = future.result()
                                    temp_evaluations[original_idx] = {
                                        "suggestion_index": original_idx,
                                        "evaluation_result": eval_result.value,
                                        "explanation": explanation,
                                        "evaluation_details": eval_data,
                                        "generated_patch": patch_used,
                                        "original_suggestion_metadata": original_suggestion
                                    }
                                except Exception as exc:
                                    print(f"    Error: Evaluating suggestion {original_idx+1} exception occurred (executor): {exc}")
                                    temp_evaluations[original_idx] = {
                                        "suggestion_index": original_idx, "evaluation_result": "Error_In_Eval",
                                        "explanation": str(exc), "evaluation_details": {},
                                        "generated_patch": patch_used, "original_suggestion_metadata": original_suggestion
                                    }

                            for i in range(len(repair_suggestions_details)):
                                if i in temp_evaluations:
                                    evaluations.append(temp_evaluations[i])
                                else:

                                    found_placeholder = False
                                    for eval_entry in evaluations:
                                        if eval_entry["suggestion_index"] == i and "Skipped" in eval_entry["evaluation_result"]:
                                            found_placeholder = True
                                            break
                                    if not found_placeholder and i not in temp_evaluations:
                                        print(f"    Warning: suggestion {i+1} not processed or skipped, adding error placeholder.")
                                        evaluations.append({
                                            "suggestion_index": i, "evaluation_result": "Error_Missed",
                                            "explanation": "Missed in processing loop", "evaluation_details": {},
                                            "generated_patch": repair_suggestions_details[i].get('suggestion_patch', ''),
                                            "original_suggestion_metadata": repair_suggestions_details[i]
                                        })

                        eval_stats = {
                            "total_suggestions": len(repair_suggestions_details),
                            "syntactic_patch_equivalent": len([e for e in evaluations if e["evaluation_result"] == "SynPatchEq"]),
                            "semantic_equivalent": len([e for e in evaluations if e["evaluation_result"] == "SemEq"]),
                            "plausible": len([e for e in evaluations if e["evaluation_result"] == "Plausible"]),
                            "incorrect": len([e for e in evaluations if e["evaluation_result"] == "Incorrect"]),
                            "unknown": len([e for e in evaluations if e["evaluation_result"] == "Unknown"])
                        }

                    result_update = {
                        "vulnerable_lines": vulnerable_line_numbers,
                        "status": "success",
                        "repairs": repair_suggestions_details
                    }

                    if enable_llm_evaluation:
                        result_update.update({
                            "llm_evaluations": evaluations,
                            "evaluation_statistics": eval_stats,
                            "ground_truth_patch": ground_truth_diff
                        })

                    result_entry.update(result_update)
                elif isinstance(repair_suggestions_details, list) and not repair_suggestions_details:
                    msg = "No suitable repair suggestions found or extracted."

                    result_entry.update({
                        "vulnerable_lines": vulnerable_line_numbers,
                        "status": "no_suggestion_found",
                        "message": msg
                    })
                else:
                    msg = f"Failed to generate repair (unexpected return: {type(repair_suggestions_details)})."

                    result_entry.update({
                        "vulnerable_lines": vulnerable_line_numbers if vulnerable_line_numbers else [],
                        "status": "error",
                        "error_message": msg
                    })
            except Exception as e:
                error_msg = f"Unexpected error during repair generation for {current_entry_identifier}: {str(e)}"
                print(f"  Critical Error for {current_entry_identifier}: {error_msg}")
                result_entry.update({
                    "vulnerable_lines": vulnerable_line_numbers if vulnerable_line_numbers else [],
                    "status": "error",
                    "error_message": error_msg
                })

    try:
        result_json_str = json.dumps(result_entry, ensure_ascii=False) + '\n'
        with open(output_json_path, 'a', encoding='utf-8') as outfile:
            outfile.write(result_json_str)
    except Exception as write_e:
        print(f"  Error writing result for {current_entry_identifier} to {output_json_path}: {write_e}")


def process_vulnerabilities_from_csv(
    csv_file_path: str,
    output_json_path: str,
    num_root_causes_to_analyze: int = 3,
    num_examples_per_cause: int = 2,
    top_n_suggestions: int = 1,
    graph_consistent: bool = False,
    verbose_graph: bool = False,
    enable_llm_evaluation: bool = True,
    generation_model_config: dict = None,
    evaluation_model_config: dict = None,
    enable_root_cause_filtering: bool = True,
    min_consistency_level: str = "Medium",
    min_confidence_score: float = 0.6,
    enable_direct_llm_fallback: bool = True,
    enable_patch_grouping: bool = False
) -> None:

    if generation_model_config is None:
        generation_model_config = {
            "provider": "openai",
            "model_name": "",
            "base_url": "",
            "api_key": '',
        }
    if evaluation_model_config is None:
        evaluation_model_config = {
            "provider": "openai",
            "model_name": "",
            "base_url": "",
            "api_key": '',
        }

    print(f"Starting PARALLEL vulnerability processing from CSV: {csv_file_path}")
    print(f"Output will be written to: {output_json_path} as JSON Lines.")

    gen_provider = generation_model_config.get('provider', 'N/A')
    gen_model_name = generation_model_config.get('model_name', 'N/A')
    print(f"Generation Model: Provider={gen_provider}, Model={gen_model_name}")

    print(f"LLM Evaluation: {'Enabled' if enable_llm_evaluation else 'Disabled'}")
    if enable_llm_evaluation:
        eval_provider = evaluation_model_config.get('provider', 'N/A')
        eval_model_name = evaluation_model_config.get('model_name', 'N/A')
        print(f"Evaluation Model: Provider={eval_provider}, Model={eval_model_name}")

    print(f"Root Cause consistency filtering: {'Enabled' if enable_root_cause_filtering else 'Disabled'} (level: {min_consistency_level}, confidence: {min_confidence_score})")
    print(f"Direct LLM repair fallback: {'Enabled' if enable_direct_llm_fallback else 'Disabled'}")
    print(f"Patch grouping enhancement algorithm: {'Enabled' if enable_patch_grouping else 'Disabled'}")

    try:
        with open(output_json_path, 'w', encoding='utf-8') as outfile:
            pass
        print(f"Output file {output_json_path} initialized (cleared).")
    except IOError as e:
        print(f"Error: Failed to initialize output file {output_json_path}: {e}")
        return

    tasks_to_submit = []
    try:
        with open(csv_file_path, mode='r', encoding='utf-8', newline='') as infile:
            reader = csv.DictReader(infile)
            if not reader.fieldnames:
                print(f"Error: CSV file {csv_file_path} is empty or has no header.")
                return

            required_columns = ['code_before', 'code_after', 'CWE ID']
            missing_columns = [col for col in required_columns if col not in reader.fieldnames]
            if missing_columns:
                print(f"Error: CSV file {csv_file_path} is missing required columns: {', '.join(missing_columns)}")
                return

            for row_idx, row_data in enumerate(reader):
                tasks_to_submit.append({
                    "row_idx": row_idx,
                    "original_code": row_data.get('code_before'),
                    "fixed_code": row_data.get('code_after'),
                    "cwe_id": row_data.get('CWE ID'),
                    "trigger_path_value": row_data.get('trigger_path'),
                    "num_root_causes_to_analyze": num_root_causes_to_analyze,
                    "num_examples_per_cause": num_examples_per_cause,
                    "top_n_suggestions": top_n_suggestions,
                    "graph_consistent": graph_consistent,
                    "verbose_graph": verbose_graph,
                    "enable_llm_evaluation": enable_llm_evaluation,

                    "generation_model_config": generation_model_config,
                    "evaluation_model_config": evaluation_model_config,
                    "enable_root_cause_filtering": enable_root_cause_filtering,
                    "min_consistency_level": min_consistency_level,
                    "min_confidence_score": min_confidence_score,
                    "enable_direct_llm_fallback": enable_direct_llm_fallback,
                    "enable_patch_grouping": enable_patch_grouping,
                    "output_json_path": output_json_path
                })

        if not tasks_to_submit:
            print(f"No tasks to process from {csv_file_path}.")

            return

        processed_count = 0

        cpu_cores = multiprocessing.cpu_count()
        max_workers = min(16, max(1, cpu_cores - 1))

        with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:

            future_to_row_idx = {
                executor.submit(
                    _process_row_and_write_result,
                    task["row_idx"], task["original_code"], task["fixed_code"], task["cwe_id"],
                    task["trigger_path_value"],
                    task["num_root_causes_to_analyze"], task["num_examples_per_cause"],
                    task["top_n_suggestions"], task["graph_consistent"], task["verbose_graph"],
                    task["enable_llm_evaluation"],

                    task["generation_model_config"],
                    task["evaluation_model_config"],
                    task["enable_root_cause_filtering"],
                    task["min_consistency_level"],
                    task["min_confidence_score"],
                    task["enable_direct_llm_fallback"],
                    task["enable_patch_grouping"],
                    task["output_json_path"]
                ): task["row_idx"] for task in tasks_to_submit
            }

        for future in concurrent.futures.as_completed(future_to_row_idx):
            row_idx_completed = future_to_row_idx[future]
            try:
                future.result()
                processed_count += 1

            except Exception as e:
                processed_count += 1

                print(f"  Error processing task for CSV row {row_idx_completed + 2}: {e}. ({processed_count}/{len(tasks_to_submit)})")

    except FileNotFoundError:
        print(f"Error: Input CSV file not found at {csv_file_path}")

    except csv.Error as csve:
        print(f"Error: CSV parsing error for file {csv_file_path}: {csve}")
    except IOError as ioe:
        print(f"Error: An I/O error occurred with {csv_file_path}: {ioe}")
    except Exception as e_global:
        print(f"An unexpected global error occurred during CSV processing or task submission: {e_global}")

    print(f"\nProcessing complete. Results are in: {output_json_path}")


def evaluate_patch_quality(
    original_vulnerable_code: str,
    generated_patch: str,
    ground_truth_patch: str,
    cwe_id: str,
    model_config: dict,

    verbose: bool = False
) -> Tuple[EvaluationResult, str, dict]:
    provider = model_config.get("provider", "openai").lower()
    llm_display_name = f"{provider.capitalize()} (Model: {model_config.get('model_name', 'default')})"

    if verbose:
        print(f"  Starting to use{llm_display_name}model to automatically evaluate patch quality (CWE: {cwe_id})...")

    evaluation_prompt = f"""
You are an expert security code reviewer evaluating a generated vulnerability fix.

**Original Vulnerable Code:**
```c
{add_line_numbers_to_code(original_vulnerable_code)}
```

**CWE Type:** {cwe_id}

**Ground Truth Patch (Reference Solution - Unified Diff Format):**
```diff
{ground_truth_patch}
```

**Generated Patch (Unified Diff Format):**
```diff
{generated_patch}
```

**Evaluation Task:**
Compare the 'Generated Patch' to the 'Ground Truth Patch' and assess its quality. Follow this evaluation order:

**1. Syntactic Patch Equivalence (SynPatchEq) (Highest Priority):**
   - Is the text content of the 'Generated Patch' **IDENTICAL** to the text content of the 'Ground Truth Patch'?
   If yes, classify as **SynPatchEq**. This is the final evaluation.

**2. Correctness Assessment (If not SynPatchEq):**
   If not SynPatchEq, evaluate if the 'Generated Patch', when applied to the 'Original Vulnerable Code', is correct:
   - Does it fully fix the vulnerability?
   - Does it maintain original functionality without breaking anything?
   - Is it technically sound?
   If it fails any of these, classify as **Incorrect**.

**3. Semantic Equivalence (If Correct but not SynPatchEq) vs. Plausible (If Correct but not SemEq):**
   If the 'Generated Patch' is Correct (and not SynPatchEq), classify its *applied effect*:
   - **SemEq**: The applied 'Generated Patch' achieves the same core security effect and functional behavior as the applied 'Ground Truth Patch'. It **must include all essential security requirements** from the 'Ground Truth Patch'. It may contain **additional, non-conflicting security checks** (redundancy is acceptable if it doesn't break functionality or introduce new vulnerabilities). The fundamental security outcome and functional preservation are equivalent, even if implementation details differ.
   - **Plausible**: The applied 'Generated Patch' is a technically sound alternative solution that fixes the vulnerability and maintains functionality. It **must include all essential security requirements** from the 'Ground Truth Patch', even if it uses a different overall approach. It may contain **additional, non-conflicting security checks** (redundancy is acceptable if it doesn't break functionality or introduce new vulnerabilities).
   - **Incorrect**: If it doesn't meet SemEq or Plausible criteria after passing Correctness.

**Output Format (JSON):**
{{
    "detailed_explanation": "Briefly explain your decision, highlighting key reasons.",
    "evaluation_result": "SynPatchEq" | "SemEq" | "Plausible" | "Incorrect",
    "confidence_level": "High/Medium/Low"
}}
Important: Be strict but fair. Focus on the definitions provided.
"""

    try:
        if verbose:
            print(f"    Calling{llm_display_name}model for patch quality evaluation...")

        api_call_params = {
            "prompt": evaluation_prompt,
            "model_config": model_config,
            "n": 1,
            "max_tokens": 5000,
            "temperature": model_config.get("temperature", DEFAULT_OPENAI_PARAMS.get("temperature", 0))
        }

        if provider == "gemini":
            model_responses = generate_with_Gemini_model(**api_call_params)
        elif provider in ["openai", "openrouter", "azure", "volcengine"]:
            model_responses = generate_with_OpenAI_model(**api_call_params)
        else:
            raise ValueError(f"Unsupported provider in model_config for evaluation: {provider}")

        if not model_responses or not model_responses[0]:
            if verbose:
                print(f"    Warning: {llm_display_name}model did not return valid evaluation response")
            return EvaluationResult.UNKNOWN, f"{llm_display_name}model evaluation failed: no response", {}

        response_text = model_responses[0].strip()

        json_match = re.search(r'```json\s*([\s\S]*?)\s*```', response_text)
        if not json_match:
            json_match = re.search(r'({[\s\S]*})', response_text)

        if json_match:
            json_str = json_match.group(1)
            try:
                evaluation_data = json.loads(json_str)

                result_str = evaluation_data.get("evaluation_result", "").strip()
                detailed_explanation = evaluation_data.get("detailed_explanation", "")

                if result_str.lower() == "synpatcheq":
                    evaluation_result = EvaluationResult.SYNTACTIC_PATCH_EQUIVALENT
                elif result_str.lower() == "semeq":
                    evaluation_result = EvaluationResult.SEMANTIC_EQUIVALENT
                elif result_str.lower() == "plausible":
                    evaluation_result = EvaluationResult.PLAUSIBLE
                elif result_str.lower() == "incorrect":
                    evaluation_result = EvaluationResult.INCORRECT
                else:
                    if verbose:
                        print(f"    Warning: Unknown evaluation result '{result_str}', marked as UNKNOWN")
                    evaluation_result = EvaluationResult.UNKNOWN

                if verbose:
                    print(f"    {llm_display_name}model evaluation result: {evaluation_result.value}")
                    print(f"    confidence: {evaluation_data.get('confidence_level', 'N/A')}")

                return evaluation_result, detailed_explanation, evaluation_data

            except json.JSONDecodeError as e:
                if verbose:
                    print(f"    Error: JSON parsing failed - {e}")
                return EvaluationResult.UNKNOWN, f"JSON parsing error: {e}", {"raw_response": response_text}
        else:
            if verbose:
                print(f"    Warning: {llm_display_name}Valid JSON format not found in model response")
            return EvaluationResult.UNKNOWN, "Response format error: JSON not found", {"raw_response": response_text}

    except Exception as e:
        if verbose:
            print(f"    Error: {llm_display_name}Exception occurred during model evaluation - {e}")
        return EvaluationResult.UNKNOWN, f"Evaluation exception: {e}", {}


def add_line_numbers_to_code(code_string: str) -> str:
    if not code_string or not code_string.strip():
        return code_string

    lines = code_string.splitlines()
    numbered_lines = [f"{i+1:3d} | {line}" for i, line in enumerate(lines)]
    return "\n".join(numbered_lines)


def format_lines_with_statements(code_string: str, line_numbers: List[int]) -> str:
    if not line_numbers:
        return "No specific lines provided."

    code_lines = code_string.splitlines()
    output_parts = []

    valid_line_numbers = []
    for item in set(line_numbers):
        try:
            ln = int(item)
            if 1 <= ln <= len(code_lines):
                valid_line_numbers.append(ln)
        except (ValueError, TypeError):

            pass

    valid_line_numbers.sort()

    if not valid_line_numbers:
        return "Provided line numbers are out of range, empty after validation, or not valid integers."

    for ln in valid_line_numbers:

        statement = code_lines[ln - 1]
        output_parts.append(f"{ln}: {statement}")

    return "\n".join(output_parts)


def evaluate_root_cause_consistency(
    current_root_cause: str,
    example_root_cause: str,
    cwe_id: str,
    model_config: dict,
    verbose: bool = False
) -> Tuple[RootCauseConsistency, str, float]:
    if verbose:
        print(f"    Evaluating Root Cause consistency (CWE: {cwe_id})...")

    consistency_prompt = f"""
You are an expert in vulnerability analysis and root cause identification. Your task is to evaluate whether two root cause descriptions are semantically consistent and refer to the same underlying vulnerability pattern.

**CWE Type:** {cwe_id}

**Current Root Cause (Analyzed for target vulnerability):**
"{current_root_cause}"

**Example Root Cause (From reference case):**
"{example_root_cause}"

**Evaluation Task:**
Compare these two root cause descriptions and determine their consistency level. Consider:

1. **Core vulnerability mechanism**: Do they describe the same fundamental security flaw?
2. **Causal chain**: Do they follow the same source→sink vulnerability path?
3. **Triggering conditions**: Are the conditions that enable the vulnerability similar?
4. **Impact scope**: Do they affect the same type of security properties?
5. **Technical context**: Are they applicable to similar code contexts?

**Consistency Levels:**
- **High**: Root causes describe essentially the same vulnerability pattern with very similar mechanisms
- **Medium**: Root causes are related and share common vulnerability aspects but differ in some details
- **Low**: Root causes have some conceptual overlap but represent different vulnerability patterns
- **Inconsistent**: Root causes describe completely different vulnerability types or mechanisms

**Important Notes:**
- Focus on semantic meaning rather than exact wording
- Consider the specific CWE type context
- Two descriptions can be consistent even if they use different technical terms
- Look for the underlying vulnerability logic, not surface-level text similarity

**Output Format:**
Provide your evaluation in the following JSON format:
{{
    "detailed_explanation": "Detailed explanation of why you assigned this consistency level",
    "key_similarities": "Main similarities between the root causes",
    "key_differences": "Main differences between the root causes",
    "consistency_level": "High" | "Medium" | "Low" | "Inconsistent",
    "confidence_score": <float between 0.0 and 1.0>,
    "recommendation": "Whether this example should be used for repair generation (Use/Consider/Avoid)"
}}

Provide only the JSON response without any additional text or formatting.
"""

    try:

        api_call_params_consistency = {
            "prompt": consistency_prompt,
            "model_config": model_config,
            "max_tokens": 5000,
            "temperature": DEFAULT_OPENAI_PARAMS.get("temperature", 0),
            "n": DEFAULT_OPENAI_PARAMS.get("n", 1)
        }

        if verbose:
            print(f"      CallingLLMEvaluating Root Cause consistency...")

        llm_responses = generate_with_OpenAI_model(**api_call_params_consistency)

        if not llm_responses or not llm_responses[0]:
            if verbose:
                print("      Warning: Root Cause consistency evaluation LLM did not return valid response")
            return RootCauseConsistency.INCONSISTENT, "LLM evaluation failed: no response", 0.0

        response_text = llm_responses[0].strip()

        json_match = re.search(r'```json\s*([\s\S]*?)\s*```', response_text)
        if not json_match:
            json_match = re.search(r'({[\s\S]*})', response_text)

        if json_match:
            json_str = json_match.group(1)
            try:
                consistency_data = json.loads(json_str)

                level_str = consistency_data.get("consistency_level", "").strip()
                confidence_score = float(consistency_data.get("confidence_score", 0.0))
                detailed_explanation = consistency_data.get("detailed_explanation", "")

                if level_str.lower() == "high":
                    consistency_level = RootCauseConsistency.HIGH
                elif level_str.lower() == "medium":
                    consistency_level = RootCauseConsistency.MEDIUM
                elif level_str.lower() == "low":
                    consistency_level = RootCauseConsistency.LOW
                elif level_str.lower() == "inconsistent":
                    consistency_level = RootCauseConsistency.INCONSISTENT
                else:
                    if verbose:
                        print(f"      Warning: Unknown consistency level '{level_str}', marked as INCONSISTENT")
                    consistency_level = RootCauseConsistency.INCONSISTENT
                    confidence_score = 0.0

                if verbose:
                    print(f"      Root Cause consistency evaluation result: {consistency_level.value}")
                    print(f"      Confidence score: {confidence_score:.2f}")
                    recommendation = consistency_data.get("recommendation", "N/A")
                    print(f"      Usage recommendation: {recommendation}")

                return consistency_level, detailed_explanation, confidence_score

            except (json.JSONDecodeError, ValueError) as e:
                if verbose:
                    print(f"      Error: Root Cause consistency JSON parsing failed - {e}")
                return RootCauseConsistency.INCONSISTENT, f"JSON parsing error: {e}", 0.0
        else:
            if verbose:
                print("      Warning: Valid JSON format not found in Root Cause consistency LLM response")
            return RootCauseConsistency.INCONSISTENT, "Response format error: JSON not found", 0.0

    except Exception as e:
        if verbose:
            print(f"      Error: Exception occurred during Root Cause consistency evaluation - {e}")
        return RootCauseConsistency.INCONSISTENT, f"Evaluation exception: {e}", 0.0


def filter_examples_by_root_cause_consistency(
    current_root_cause: str,
    examples: List[dict],
    cwe_id: str,
    model_config: dict,
    min_consistency_level: RootCauseConsistency = RootCauseConsistency.MEDIUM,
    min_confidence_score: float = 0.6,
    verbose: bool = False
) -> List[dict]:
    if not examples:
        return []

    if verbose:
        print(f"    Starting to filter based on Root Cause consistency {len(examples)}  examples...")

    filtered_examples = []
    consistency_levels_order = {
        RootCauseConsistency.HIGH: 4,
        RootCauseConsistency.MEDIUM: 3,
        RootCauseConsistency.LOW: 2,
        RootCauseConsistency.INCONSISTENT: 1
    }

    min_level_value = consistency_levels_order.get(min_consistency_level, 3)

    level_stats = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Inconsistent": 0,
        "Missing": 0
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        future_to_example_info = {}
        for idx, example_data in enumerate(examples):
            example_root_cause = example_data.get("pre_repair_state_example", "")

            if not example_root_cause or example_root_cause == "Not available":
                level_stats["Missing"] += 1
                if verbose:
                    print(f"      Example {idx+1}: skip(missing root cause information)")
                continue

            future = executor.submit(evaluate_root_cause_consistency,
                                     current_root_cause=current_root_cause,
                                     example_root_cause=example_root_cause,
                                     cwe_id=cwe_id,
                                     model_config=model_config,
                                     verbose=verbose)
            future_to_example_info[future] = (idx, example_data)

        for future in concurrent.futures.as_completed(future_to_example_info):
            idx, original_example_data = future_to_example_info[future]
            try:
                consistency_level, explanation, confidence_score = future.result()

                level_stats[consistency_level.value] += 1

                level_value = consistency_levels_order.get(consistency_level, 1)

                if level_value >= min_level_value and confidence_score >= min_confidence_score:

                    enhanced_example = original_example_data.copy()
                    enhanced_example.update({
                        "root_cause_consistency_level": consistency_level.value,
                        "root_cause_confidence_score": confidence_score,
                        "root_cause_consistency_explanation": explanation
                    })
                    filtered_examples.append(enhanced_example)

                    if verbose:
                        print(f"      Example {idx+1}: retained ({consistency_level.value}, confidence: {confidence_score:.2f})")
                else:
                    if verbose:
                        reason = "Insufficient level" if level_value < min_level_value else "Insufficient confidence"
                        print(f"      Example {idx+1}: filtered out ({consistency_level.value}, confidence: {confidence_score:.2f}) - {reason}")
            except Exception as exc:
                print(f"      Error evaluating consistency for example {idx+1} (original data: {str(original_example_data)[:100]}...): {exc}")

    if verbose:
        print(f"    Root Cause consistency filtering statistics:")
        print(f"      Total examples: {len(examples)}")
        print(f"      Level distribution: High={level_stats['High']}, Medium={level_stats['Medium']}, Low={level_stats['Low']}, Inconsistent={level_stats['Inconsistent']}, Missing={level_stats['Missing']}")
        print(f"      Filter requirements: min level={min_consistency_level}, min confidence={min_confidence_score}")
        print(f"      Final retained: {len(filtered_examples)}  examples")
    else:
        print(f"    Root Cause consistency filtering completed: {len(filtered_examples)}/{len(examples)}  examplesretained")

    return filtered_examples


def main():
    dataset = "APPatch"
    process_vulnerabilities_from_csv(
        csv_file_path=f"datasets/{dataset}/processed_vulnerabilities.csv",
        output_json_path=f"datasets/{dataset}/results_output.json",
        num_root_causes_to_analyze=5,
        num_examples_per_cause=5,
        top_n_suggestions=5,
        graph_consistent=True,
        verbose_graph=False,
        enable_llm_evaluation=True,
        enable_root_cause_filtering=True,
        min_consistency_level="Medium",
        min_confidence_score=0.6,
        enable_direct_llm_fallback=True,
        enable_patch_grouping=True
    )


if __name__ == '__main__':
    main()
