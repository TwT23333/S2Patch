import csv
import json
import os
import re
import difflib
import logging
import concurrent.futures
from models.OpenAI_API import generate_with_OpenAI_model
from utils.dataprocess import add_headers_and_ids_to_csv
from tqdm import tqdm
from slicer.parse_joern_output2 import slice_code_from_string


def add_line_numbers_to_code(code_string: str) -> str:
    if not code_string or not code_string.strip():
        return code_string

    lines = code_string.splitlines()
    numbered_lines = [f"{i+1} | {line}" for i, line in enumerate(lines)]
    return "\n".join(numbered_lines)


def generate_unified_diff(code_before_str: str, code_after_str: str, fromfile: str = 'before', tofile: str = 'after', n: int = 3) -> str:
    if not isinstance(code_before_str, str) or not isinstance(code_after_str, str):

        return "Error: Input code strings must be valid strings for diff generation."

    code_before_lines = code_before_str.splitlines(keepends=True)
    code_after_lines = code_after_str.splitlines(keepends=True)

    diff = difflib.unified_diff(code_before_lines, code_after_lines, fromfile=fromfile, tofile=tofile, n=n)
    return "".join(diff)


def parse_llm3_evaluation(llm_response_text: str) -> tuple[bool, str]:
    is_correct = False
    feedback = "LLM3 response format error or missing, or feedback not extracted."

    result_match = re.search(r"Result:\s*(Correct|Incorrect)", llm_response_text, re.IGNORECASE)
    if result_match:
        is_correct = result_match.group(1).lower() == "correct"

    feedback_match = re.search(r"Feedback:\s*(.*)", llm_response_text, re.DOTALL | re.IGNORECASE)
    if feedback_match:
        feedback = feedback_match.group(1).strip()
    elif result_match:
        if is_correct:
            feedback = "LLM3 evaluated as Correct. Specific feedback line not found."
        else:
            feedback = "LLM3 evaluated as Incorrect. Specific feedback line not found."

    return is_correct, feedback


def parse_llm1_strategy(llm_response_text: str) -> dict:
    results = {
        "vulnerability_source_precise": "N/A",
        "vulnerability_sink_precise": "N/A",
        "vulnerability_path_description": "N/A",
        "cwe_specific_strategy": "N/A",
        "pre_repair_state": "N/A",
        "abstract_strategy": "N/A",
        "concrete_strategy": "N/A",
        "post_repair_state": "N/A",
        "parsing_status": "failed"
    }

    vs_match = re.search(r"Vulnerability Source \(Precise\):\s*(.*?)(?=\s*Vulnerability Sink \(Precise\):|\s*CWE-Specific Repair Strategy:|\Z)", llm_response_text, re.DOTALL | re.IGNORECASE)
    if vs_match and vs_match.group(1).strip():
        results["vulnerability_source_precise"] = vs_match.group(1).strip()

    vk_match = re.search(r"Vulnerability Sink \(Precise\):\s*(.*?)(?=\s*Vulnerability Path Description:|\s*CWE-Specific Repair Strategy:|\Z)", llm_response_text, re.DOTALL | re.IGNORECASE)
    if vk_match and vk_match.group(1).strip():
        results["vulnerability_sink_precise"] = vk_match.group(1).strip()

    vp_match = re.search(r"Vulnerability Path Description:\s*(.*?)(?=\s*CWE-Specific Repair Strategy:|\s*Pre-Repair State:|\Z)", llm_response_text, re.DOTALL | re.IGNORECASE)
    if vp_match and vp_match.group(1).strip():
        results["vulnerability_path_description"] = vp_match.group(1).strip()

    cwe_specific_match = re.search(r"CWE-Specific Repair Strategy:\s*(.*?)(?=\s*Pre-Repair State:|\Z)", llm_response_text, re.DOTALL | re.IGNORECASE)
    if cwe_specific_match and cwe_specific_match.group(1).strip():
        results["cwe_specific_strategy"] = cwe_specific_match.group(1).strip()

    pre_match = re.search(r"Pre-Repair State:\s*(.*?)(?=\s*Repair Strategy:|\Z)", llm_response_text, re.DOTALL | re.IGNORECASE)
    if pre_match and pre_match.group(1).strip():
        results["pre_repair_state"] = pre_match.group(1).strip()

    strategy_block_text = None

    strategy_block_match = re.search(r"Repair Strategy:\s*(.*?)(?=\s*Post-Repair State:|\Z)", llm_response_text, re.DOTALL | re.IGNORECASE)
    if strategy_block_match:
        strategy_block_text = strategy_block_match.group(1).strip()

    if strategy_block_text:

        abstract_match = re.search(r"Abstract:\s*(.*?)(?=\s*Concrete:|\Z)", strategy_block_text, re.DOTALL | re.IGNORECASE)
        if abstract_match and abstract_match.group(1).strip():
            results["abstract_strategy"] = abstract_match.group(1).strip()

        concrete_match = re.search(r"Concrete:\s*(.*)", strategy_block_text, re.DOTALL | re.IGNORECASE)
        if concrete_match and concrete_match.group(1).strip():
            results["concrete_strategy"] = concrete_match.group(1).strip()
    else:

        abstract_fallback_match = re.search(r"Repair Strategy:\s*Abstract:\s*(.*?)(?=\s*Concrete:|\s*Post-Repair State:|\Z)", llm_response_text, re.DOTALL | re.IGNORECASE)
        if abstract_fallback_match and abstract_fallback_match.group(1).strip():
            results["abstract_strategy"] = abstract_fallback_match.group(1).strip()

        concrete_fallback_match = re.search(r"Repair Strategy:(?:.|\n)*?Concrete:\s*(.*?)(?=\s*Post-Repair State:|\Z)", llm_response_text, re.DOTALL | re.IGNORECASE)
        if concrete_fallback_match and concrete_fallback_match.group(1).strip():
            results["concrete_strategy"] = concrete_fallback_match.group(1).strip()

    post_match = re.search(r"Post-Repair State:\s*(.*)", llm_response_text, re.DOTALL | re.IGNORECASE)
    if post_match and post_match.group(1).strip():
        results["post_repair_state"] = post_match.group(1).strip()

    found_parts_count = 0
    if results["cwe_specific_strategy"] != "N/A":
        found_parts_count += 1
    if results["pre_repair_state"] != "N/A":
        found_parts_count += 1
    if results["abstract_strategy"] != "N/A":
        found_parts_count += 1
    if results["concrete_strategy"] != "N/A":
        found_parts_count += 1
    if results["post_repair_state"] != "N/A":
        found_parts_count += 1

    if found_parts_count == 5:
        results["parsing_status"] = "success"
    elif found_parts_count > 0:
        results["parsing_status"] = "partial"

    return results


def parse_llm1a_output(llm1a_response_text: str) -> dict:
    parsed_data = {
        "sources": [],
        "sinks": [],
        "all_candidate_lines": []
    }

    if not llm1a_response_text or not llm1a_response_text.strip():
        return parsed_data

    try:
        json_str = ""

        json_match_fenced = re.search(r"```json\s*([\s\S]*?)\s*```", llm1a_response_text, re.DOTALL)
        if json_match_fenced:
            json_str = json_match_fenced.group(1).strip()
        else:

            first_char_json = -1
            last_char_json = -1

            first_brace = llm1a_response_text.find('{')
            first_bracket = llm1a_response_text.find('[')

            if first_brace != -1 and (first_bracket == -1 or first_brace < first_bracket):
                first_char_json = first_brace
            elif first_bracket != -1:
                first_char_json = first_bracket

            if first_char_json != -1:

                if llm1a_response_text[first_char_json] == '{':
                    last_char_json = llm1a_response_text.rfind('}')
                else:
                    last_char_json = llm1a_response_text.rfind(']')

                if last_char_json > first_char_json:
                    json_str = llm1a_response_text[first_char_json: last_char_json + 1]
                else:
                    if llm1a_response_text.strip().startswith(("{", "[")):
                        json_str = llm1a_response_text.strip()

        if not json_str:

            return parsed_data

        data = json.loads(json_str)

        sources = data.get("sources", [])
        sinks = data.get("sinks", [])
        all_lines_set = set()

        if isinstance(sources, list):
            for item in sources:
                if isinstance(item, dict) and "name" in item and isinstance(item.get("lines"), list):
                    valid_lines = [line for line in item["lines"] if isinstance(line, int) and line > 0]
                    if valid_lines:
                        parsed_data["sources"].append({"name": str(item["name"]), "lines": valid_lines})
                        for line in valid_lines:
                            all_lines_set.add(line)

        if isinstance(sinks, list):
            for item in sinks:
                if isinstance(item, dict) and "name" in item and isinstance(item.get("lines"), list):
                    valid_lines = [line for line in item["lines"] if isinstance(line, int) and line > 0]
                    if valid_lines:
                        parsed_data["sinks"].append({"name": str(item["name"]), "lines": valid_lines})
                        for line in valid_lines:
                            all_lines_set.add(line)

        parsed_data["all_candidate_lines"] = sorted(list(all_lines_set))

    except json.JSONDecodeError:

        pass
    except Exception:

        pass

    return parsed_data


def _process_row(row_tuple, openai_api_params, max_iterations, logger):
    original_row_index, row = row_tuple
    logger.info(f"--- Starting to process row {original_row_index + 1} ---")
    current_row_failed = False
    try:
        code_before = row['code_before']
        code_after = row['code_after']
        cwe_type = row['cwe_type']
        cve_id = row['cve_id']

        if not code_before.strip() or not code_after.strip():
            logger.warning(f"Row {original_row_index + 1}: 'code_before' or 'code_after' is empty, skipping this row.")
            return {
                "original_row_index": original_row_index + 1, "error": "Empty code_before or code_after",
                "cwe_type": cwe_type, "cve_id": cve_id, "code_before": code_before, "code_after_ground_truth": code_after,
                "status": "failed"
            }

        logger.info(f"Row {original_row_index + 1}: Step A: Performing initial code slicing (code_before)...")

        unified_diff_ground_truth = generate_unified_diff(code_before, code_after, fromfile=f"{cve_id}_before.txt", tofile=f"{cve_id}_after_ground_truth.txt")
        logger.info(f"Row {original_row_index + 1}: Ground Truth Unified Diff (preview): {unified_diff_ground_truth[:200]}...")

        logger.info(f"Row {original_row_index + 1}: Phase 1 (LLM1a): Initial identification of candidate Source/Sink...")
        code_before_numbered = add_line_numbers_to_code(code_before)

        prompt_llm1a = f"""Analyze the Original Vulnerable Code and its Patched version below.
CWE Type: {cwe_type}
Original Vulnerable Code:
```
{code_before_numbered}
```
Patched Code (unified diff):
```
{unified_diff_ground_truth}
```
Task: Identify potential **Sources** (where tainted data originates or a vulnerability condition starts) and **Sinks** (where the tainted data is used unsafely or the vulnerability manifests) in the `Original Vulnerable Code` related to the `{cwe_type}` vulnerability.
When reporting line numbers, use the line numbers provided in the `Original Vulnerable Code` block above.
For each Source and Sink, list the relevant variable or function names and all specific line numbers in the `Original Vulnerable Code` where they appear.
The variables and functions included in a source/sink should be as concise as possible while still clearly demonstrating the root cause of the vulnerability.

First, carefully reason the vulnerability step by strp, then, Output STRICTLY in the following JSON format:
```json
{{
  "sources": [
    {{"name": "variable_or_function_name", "lines": [line_num1]}},
    ...
  ],
  "sinks": [
    {{"name": "variable_or_function_name", "lines": [line_num2]}},
    ...
  ]
}}
```
If no specific sources or sinks can be identified, output an empty list for "sources" and/or "sinks".
"""
        llm1a_api_params = {"n": 1}
        if openai_api_params:
            llm1a_api_params.update(openai_api_params)
        if "stop" in llm1a_api_params and isinstance(llm1a_api_params["stop"], str):
            llm1a_api_params["stop"] = [llm1a_api_params["stop"]]
        llm1a_api_params["prompt"] = prompt_llm1a

        llm_response_llm1a_list = generate_with_OpenAI_model(**llm1a_api_params)

        if llm_response_llm1a_list and isinstance(llm_response_llm1a_list, list) and llm_response_llm1a_list[0]:
            llm1a_raw_output = llm_response_llm1a_list[0].strip()
            logger.info(f"Row {original_row_index + 1}: LLM1a raw output (preview): {llm1a_raw_output[:150]}...")
            llm1a_parsed_candidates = parse_llm1a_output(llm1a_raw_output)
            candidate_line_numbers_for_slice = llm1a_parsed_candidates.get("all_candidate_lines", [])
        else:
            logger.warning(f"Row {original_row_index + 1}: LLM1a failed to generate candidate source/sink.")
            llm1a_raw_output = "Error or empty response from LLM1a"

        if candidate_line_numbers_for_slice:
            logger.info(f"Row {original_row_index + 1}: Phase 2: Generating focused code slice based on LLM1a identified line numbers {candidate_line_numbers_for_slice}...")
            try:

                slice_result, _ = slice_code_from_string(
                    source_code=code_before,
                    target_lines=candidate_line_numbers_for_slice,
                    slice_type="combined",
                    data_flow_only=True,
                    verbose=False
                )
                focused_vuln_slice_before = slice_result if slice_result else "Slice generation returned empty."
                logger.info(f"Row {original_row_index + 1}: Focused code slice (preview): {focused_vuln_slice_before[:150]}...")
            except NameError:
                logger.error(f"Row {original_row_index + 1}: slice_code_from_string function is not defined, cannot generate focused slice.")
                focused_vuln_slice_before = "Error: slice_code_from_string not defined."
            except Exception as e_slice:
                logger.error(f"Row {original_row_index + 1}: Error occurred while generating focused code slice: {e_slice}")
                focused_vuln_slice_before = f"Error during focused slice generation: {e_slice}"
        else:
            logger.info(f"Row {original_row_index + 1}: LLM1a did not provide candidate line numbers, skipping focused code slice generation.")
            focused_vuln_slice_before = "No candidate lines from LLM1a for focused slice."

        current_iteration = 0
        llm1_feedback_for_next_iteration = ""

        llm1_strategy_history = []
        llm2_repaired_code_history = []
        llm3_evaluation_history = []

        final_llm1_strategy_raw = "N/A"
        final_llm1_cwe_specific_strategy = "N/A"
        final_llm1_pre_repair_state = "N/A"
        final_llm1_abstract_strategy = "N/A"
        final_llm1_concrete_strategy = "N/A"
        final_llm1_post_repair_state = "N/A"
        final_llm1_parsing_status = "N/A"

        final_llm1_precise_source = "N/A"
        final_llm1_precise_sink = "N/A"
        final_llm1_vulnerability_path = "N/A"

        final_llm2_repaired_code = "N/A"
        final_llm3_evaluation_correct = False
        final_llm3_feedback = "N/A"

        current_api_params_row = {"n": 1}
        if openai_api_params:
            current_api_params_row.update(openai_api_params)
        if "stop" in current_api_params_row and isinstance(current_api_params_row["stop"], str):
            current_api_params_row["stop"] = [current_api_params_row["stop"]]

        while current_iteration <= max_iterations:
            logger.info(f"Row {original_row_index + 1}: --- Starting iteration {current_iteration + 1} / {max_iterations + 1} ---")

            logger.info(f"Row {original_row_index + 1}: Phase 3 (LLM1b): Fine-grained analysis and strategy generation...")
            if current_iteration == 0:
                prompt_llm1 = f"""Analyze the following vulnerability fix to understand the vulnerability, its root cause, precise source/sink/path, the repair strategy, and the state after repair.
When reporting line numbers for Source and Sink, refer to the line numbers in the 'Original Vulnerable (Before Fix) Code'.

CWE Type: {cwe_type}
Original Vulnerable (Before Fix) Code:
```
{code_before_numbered}
```
Unified Diff of Patched Code:
```diff
{unified_diff_ground_truth}
```
Focused Code Slice:
```
{focused_vuln_slice_before}
```
Based on ALL the provided information, provide the following components. Ensure your descriptions are abstract where specified for strategies and states. For precise identification of source, sink, and path, you MUST use the line numbers as they appear in the 'Original Vulnerable (Before Fix) Code' block ONLY. Do NOT use line numbers from any other code snippets or slices provided (e.g., 'Original (Before Fix) Code Slice', 'Focused Code Slice'), as their line numbering is internal to those snippets and not relevant for the final precise location reporting:
1.  **Vulnerability Source (Precise)**:
    *   Identify the precise source of the vulnerability in the 'Original Vulnerable Code'.
2.  **Vulnerability Sink (Precise)**:
    *   Identify the precise sink of the vulnerability in the 'Original Vulnerable Code'.
3.  **Vulnerability Path Description**:
    *   Describe the path or conditions from the source to the sink that constitute the vulnerability.
4.  **Pre-Repair State (Root Cause of Vulnerability)**:
    *   Describe the state of the program *before* the repair, focusing on the abstract root cause of the vulnerability related to the source/sink and Path Description.
5.  **CWE-Specific Repair Strategy**:
    *   Based on your knowledge of CWE Type '{cwe_type}',the vulnerability fix above and the root cause, describe a specific strategy for repairing the vulnerability tailored to this vulnerability type.
6.  **Repair Strategy**:
    *   **Abstract Repair Strategy**: Describe the general, high-level and step-by-step approach to patch the vulnerability as observed from the provided before/after code and the root cause. This description should NOT include specific code statements or identifiers from the *original vulnerable code* unless illustrating a general pattern. This strategy must be precise enough for repairing the vulnerability in the conceptual sense.
    *   **Concrete Repair Strategy**: Describe the specific, actionable steps to transform the 'Original Vulnerable Code' into a correctly patched version. This strategy must be precise enough for developers to apply.
7.  **Post-Repair State**:
    *   Describe the state of the program *after* the repair, focusing on how the vulnerability is resolved in an abstract manner related to its root cause.

Output the analysis STRICTLY in the following format:
Vulnerability Source (Precise):
[Your precise source identification]
Vulnerability Sink (Precise):
[Your precise sink identification]
Vulnerability Path Description:
[Your vulnerability path description]
CWE-Specific Repair Strategy:
[Your CWE-specific repair strategy]
Pre-Repair State:
[Your analysis of the pre-repair state and root cause]
Repair Strategy:
  Abstract: [Your abstract repair strategy based on observed changes]
  Concrete: [Your concrete repair strategy based on observed changes]
Post-Repair State:
[Your analysis of the post-repair state]"""
            else:
                prompt_llm1 = f"""Re-analyze the code based on previous feedback.
CWE Type: {cwe_type}
Original Vulnerable (Before Fix) Code:
```
{code_before_numbered}
```
Unified Diff of Patched Code (Reference, against Original Vulnerable Code):
```diff
{unified_diff_ground_truth}
```
Focused Code Slice based on LLM1a Candidates (from Original Vulnerable Code, line numbers refer to original):
```
{focused_vuln_slice_before}
```
A previous attempt to generate a repair strategy and apply it resulted in the following feedback from an evaluator:
"{llm1_feedback_for_next_iteration}"

!!!Important: Considering this feedback, please provide a revised and improved analysis with the following components. Ensure your descriptions are abstract where specified for strategies and states. For precise identification of source, sink, and path, you MUST use the line numbers as they appear in the 'Original Vulnerable (Before Fix) Code' block ONLY. Do NOT use line numbers from any other code snippets or slices provided (e.g., 'Original (Before Fix) Code Slice', 'Focused Code Slice'), as their line numbering is internal to those snippets and not relevant for the final precise location reporting:
1.  **Vulnerability Source (Precise)**:
    *   Re-evaluate and identify the precise source of the vulnerability.
2.  **Vulnerability Sink (Precise)**:
    *   Re-evaluate and identify the precise sink of the vulnerability.
3.  **Vulnerability Path Description**:
    *   Re-evaluate and describe the vulnerability path.
4.  **CWE-Specific Repair Strategy**:
    *   Re-evaluate and refine this based on feedback and all available context.
5.  **Pre-Repair State (Root Cause of Vulnerability)**:
    *   Re-evaluate and describe the pre-repair state.
6.  **Repair Strategy (General, based on observed changes)**:
    *   **Abstract Repair Strategy**: Re-evaluate and describe.
    *   **Concrete Repair Strategy**: Re-evaluate and describe.
7.  **Post-Repair State**:
    *   Re-evaluate and describe the post-repair state.

Output the revised analysis STRICTLY in the following format:
Vulnerability Source (Precise):
[Your revised precise source identification]
Vulnerability Sink (Precise):
[Your revised precise sink identification]
Vulnerability Path Description:
[Your revised vulnerability path description]
CWE-Specific Repair Strategy:
[Your revised CWE-specific repair strategy]
Pre-Repair State:
[Your revised analysis of the pre-repair state and root cause]
Repair Strategy:
  Abstract: [Your revised abstract repair strategy based on observed changes]
  Concrete: [Your revised concrete repair strategy based on observed changes]
Post-Repair State:
[Your revised analysis of the post-repair state]"""

            current_api_params_row["prompt"] = prompt_llm1
            llm_response_llm1 = generate_with_OpenAI_model(**current_api_params_row)
            current_fix_strategy = ""
            if llm_response_llm1 and isinstance(llm_response_llm1, list) and llm_response_llm1[0]:
                current_fix_strategy = llm_response_llm1[0].strip()
                logger.info(f"Row {original_row_index + 1}: LLM1 generated strategy (preview): {current_fix_strategy[:100]}...")
            else:
                logger.warning(f"Row {original_row_index + 1}: LLM1 failed to generate repair strategy.")
                current_fix_strategy = "Error or empty response from LLM1"
                llm1_strategy_history.append(current_fix_strategy)
                current_row_failed = True
                break

            parsed_llm1_strategy_parts = parse_llm1_strategy(current_fix_strategy)
            llm1_strategy_history.append(parsed_llm1_strategy_parts)

            final_llm1_strategy_raw = current_fix_strategy
            final_llm1_precise_source = parsed_llm1_strategy_parts.get("vulnerability_source_precise", "N/A")
            final_llm1_precise_sink = parsed_llm1_strategy_parts.get("vulnerability_sink_precise", "N/A")
            final_llm1_vulnerability_path = parsed_llm1_strategy_parts.get("vulnerability_path_description", "N/A")
            final_llm1_cwe_specific_strategy = parsed_llm1_strategy_parts.get("cwe_specific_strategy", "N/A")
            final_llm1_pre_repair_state = parsed_llm1_strategy_parts.get("pre_repair_state", "N/A")
            final_llm1_abstract_strategy = parsed_llm1_strategy_parts.get("abstract_strategy", "N/A")
            final_llm1_concrete_strategy = parsed_llm1_strategy_parts.get("concrete_strategy", "N/A")
            final_llm1_post_repair_state = parsed_llm1_strategy_parts.get("post_repair_state", "N/A")
            final_llm1_parsing_status = parsed_llm1_strategy_parts.get("parsing_status", "failed")

            logger.info(f"Row {original_row_index + 1}: LLM2: Applying strategy to repair code...")
            prompt_llm2 = f"""CWE Type: {cwe_type}
Original Vulnerable Code:
```
{code_before}
```
You are tasked to repair the 'Original Vulnerable Code'.
Use the following strategies derived from an analysis of the vulnerability and a reference patch:
CWE Number: {cwe_type}
CWE-Specific Repair Strategy:
{parsed_llm1_strategy_parts['cwe_specific_strategy']}
Abstract Repair Strategy:
{parsed_llm1_strategy_parts['abstract_strategy']}
Concrete Repair Strategy:
{parsed_llm1_strategy_parts['concrete_strategy']}
Based on the "Abstract Repair Strategy" and "Concrete Repair Strategy", generate a unified diff patch to repair the vulnerability in the 'Original Vulnerable Code'.
Concentrate on the vulnerable section(s); avoid modifying any non-vulnerable or unrelated areas.

Output Format:
Respond STRICTLY with a single JSON object containing the following keys:
- "patch_diff": A string containing the unified diff patch for fixing the 'Original Vulnerable Code'. This should be in standard unified diff format showing exactly what lines to change.
- "repair_strategy": A concise string describing the strategy or approach taken to repair the vulnerability.

Example JSON Output:
{{
  "repair_strategy": "Input validation was added to sanitize user-provided data before buffer operations.",
  "patch_diff": "@@ -10,3 +10,6 @@\\n     char buffer[100];\\n-    strcpy(buffer, input);\\n+    if (strlen(input) < sizeof(buffer)) {{\\n+        strcpy(buffer, input);\\n+    }}\\n     return buffer;"
}}

Important:
- The "patch_diff" should be a valid unified diff that can be applied to the original vulnerable code
- Focus on the minimal changes needed to fix the vulnerability
- Ensure the patch maintains the original code's functionality while addressing the security issue
- Do not include any explanations, preamble, or markdown formatting around the JSON object
- The patch should be applicable using standard patch tools"""
            current_api_params_row["prompt"] = prompt_llm2
            llm_response_llm2 = generate_with_OpenAI_model(**current_api_params_row)
            patch_diff_by_llm2 = ""
            repair_strategy_llm2 = ""
            if llm_response_llm2 and isinstance(llm_response_llm2, list) and llm_response_llm2[0]:
                llm2_raw_output = llm_response_llm2[0].strip()
                try:

                    processed_text = llm2_raw_output
                    if processed_text.startswith("```json"):
                        match = re.search(r"```json\s*([\s\S]*?)\s*```$", processed_text, re.DOTALL)
                        if match:
                            processed_text = match.group(1).strip()
                    elif processed_text.startswith("```"):
                        match = re.search(r"```\s*([\s\S]*?)\s*```$", processed_text, re.DOTALL)
                        if match:
                            processed_text = match.group(1).strip()

                    parsed_json = json.loads(processed_text)

                    patch_diff_by_llm2 = parsed_json.get("patch_diff", "")
                    repair_strategy_llm2 = parsed_json.get("repair_strategy", "")

                    if not isinstance(patch_diff_by_llm2, str) or not patch_diff_by_llm2.strip():
                        logger.warning(f"Row {original_row_index + 1}: LLM2 response JSON 'patch_diff' is missing, not a string, or empty. Response: '{llm2_raw_output[:200]}...'")
                        patch_diff_by_llm2 = f"Error: LLM2 failed to generate valid patch_diff. Raw output: {llm2_raw_output[:200]}..."
                        llm2_repaired_code_history.append(patch_diff_by_llm2)
                        current_row_failed = True
                        break
                    if not isinstance(repair_strategy_llm2, str) or not repair_strategy_llm2.strip():
                        logger.warning(f"Row {original_row_index + 1}: LLM2 response JSON 'repair_strategy' is missing, not a string, or empty. Response: '{llm2_raw_output[:200]}...'")
                        repair_strategy_llm2 = "Error: repair_strategy not provided by LLM2"

                    logger.info(f"Row {original_row_index + 1}: LLM2 generated repair patch (Patch Diff preview): {patch_diff_by_llm2[:200]}...")

                except json.JSONDecodeError:
                    logger.warning(f"Row {original_row_index + 1}: Failed to decode LLM2 response as JSON. Response: '{llm2_raw_output[:200]}...'")
                    patch_diff_by_llm2 = f"Error: JSON decode failed. Raw output: {llm2_raw_output[:200]}..."
                    llm2_repaired_code_history.append(patch_diff_by_llm2)
                    current_row_failed = True
                    break
                except Exception as e:
                    logger.warning(f"Row {original_row_index + 1}: Unexpected error processing LLM2 response: {e}. Response: '{llm2_raw_output[:200]}...'")
                    patch_diff_by_llm2 = f"Error: Processing failed. Raw output: {llm2_raw_output[:200]}..."
                    llm2_repaired_code_history.append(patch_diff_by_llm2)
                    current_row_failed = True
                    break
            else:
                logger.warning(f"Row {original_row_index + 1}: LLM2 failed to generate repair code.")
                patch_diff_by_llm2 = "Error or empty response from LLM2"
                llm2_repaired_code_history.append(patch_diff_by_llm2)
                current_row_failed = True
                break

            llm2_repaired_code_history.append({
                "patch_diff": patch_diff_by_llm2,
                "repair_strategy": repair_strategy_llm2
            })
            final_llm2_repaired_code = patch_diff_by_llm2

            logger.info(f"Row {original_row_index + 1}: LLM3: Evaluating repair result...")

            prompt_llm3 = f"""CWE Type: {cwe_type}
            Original Vulnerable Code:
            ```
            {code_before}
            ```
            Generated Patch (Unified Diff by LLM2):
            ```diff
            {patch_diff_by_llm2}
            ```
            Reference Ground Truth Patch (Unified Diff):
            ```diff
            {unified_diff_ground_truth}
            ```
            Task: Evaluate if the 'Generated Patch (Unified Diff by LLM2)' is a correct and suitable fix for the vulnerability in the 'Original Vulnerable Code' when compared against the 'Reference Ground Truth Patch (Unified Diff)'.

Consider the following:
1. Does the 'Generated Patch' successfully apply the core idea of the fix present in the 'Reference Ground Truth Patch'?
2. Does it address the vulnerability implied by the CWE type?
3. Is the 'Generated Patch' semantically equivalent or plausible compared to the 'Reference Ground Truth Patch' in terms of fixing the issue?
4. Are there any introduced errors or regressions in the 'Generated Patch'?

Focus on:
- Security effectiveness: Does the generated patch eliminate the vulnerability like the ground truth does?
- Functional correctness: Does the patch maintain the original intended functionality?
- Implementation quality: Is the approach reasonable and safe?
- Compare semantic meaning and security outcomes rather than exact code matching

Output your evaluation STRICTLY in the following format:
Result: [Correct/Incorrect]
Feedback: [Provide detailed feedback if Incorrect, explaining why the repair is not suitable, what's missing, or what's wrong. If Correct, briefly state "The repair appears correct and aligns with the reference." or similar.]"""
            current_api_params_row["prompt"] = prompt_llm3
            llm_response_llm3 = generate_with_OpenAI_model(**current_api_params_row)

            evaluation_correct_current = False
            llm1_feedback_for_next_iteration = "Error or empty response from LLM3"

            if llm_response_llm3 and isinstance(llm_response_llm3, list) and llm_response_llm3[0]:
                raw_llm3_output = llm_response_llm3[0].strip()
                logger.info(f"Row {original_row_index + 1}: LLM3 raw output (preview): {raw_llm3_output[:150]}...")
                evaluation_correct_current, llm1_feedback_for_next_iteration = parse_llm3_evaluation(raw_llm3_output)
                logger.info(f"Row {original_row_index + 1}: LLM3 evaluation result: {'Correct' if evaluation_correct_current else 'Incorrect'}. Feedback: {llm1_feedback_for_next_iteration[:100]}...")
            else:
                logger.warning(f"Row {original_row_index + 1}: LLM3 failed to generate evaluation result.")

            llm3_evaluation_history.append({
                "iteration": current_iteration + 1,
                "strategy_used": parsed_llm1_strategy_parts,
                "repaired_code_generated": final_llm2_repaired_code,
                "evaluation_is_correct": evaluation_correct_current,
                "evaluator_feedback": llm1_feedback_for_next_iteration
            })
            final_llm3_evaluation_correct = evaluation_correct_current
            final_llm3_feedback = llm1_feedback_for_next_iteration

            if evaluation_correct_current:
                logger.info(f"Row {original_row_index + 1}: Iteration {current_iteration + 1}: LLM3 evaluated as correct. Ending processing for this row.")
                break

            current_iteration += 1
            if current_iteration > max_iterations:
                logger.info(f"Row {original_row_index + 1}: Maximum iterations reached ({max_iterations + 1} attempts).")

        status = "failed" if current_row_failed else "success"
        if not current_row_failed:
            iterations_attempted = current_iteration + 1 if final_llm3_evaluation_correct else current_iteration
        else:
            iterations_attempted = current_iteration

        result_item = {
            "original_row_index": original_row_index + 1,
            "cwe_type": cwe_type,
            "cve_id": cve_id,
            "code_before": code_before,
            "code_after_ground_truth": code_after,

            "llm1a_raw_output": llm1a_raw_output,
            "llm1a_parsed_candidates": llm1a_parsed_candidates,
            "candidate_line_numbers_for_slice": candidate_line_numbers_for_slice,
            "focused_vuln_slice_before": focused_vuln_slice_before,


            "max_iterations_configured": max_iterations,
            "iterations_attempted": iterations_attempted,

            "final_llm1_strategy_raw": final_llm1_strategy_raw,
            "final_llm1_precise_source": final_llm1_precise_source,
            "final_llm1_precise_sink": final_llm1_precise_sink,
            "final_llm1_vulnerability_path": final_llm1_vulnerability_path,
            "final_llm1_cwe_specific_strategy": final_llm1_cwe_specific_strategy,
            "final_llm1_pre_repair_state": final_llm1_pre_repair_state,
            "final_llm1_abstract_strategy": final_llm1_abstract_strategy,
            "final_llm1_concrete_strategy": final_llm1_concrete_strategy,
            "final_llm1_post_repair_state": final_llm1_post_repair_state,
            "final_llm1_parsing_status": final_llm1_parsing_status,

            "final_llm2_generated_patch": patch_diff_by_llm2 if 'patch_diff_by_llm2' in locals() else "Error: patch_diff_by_llm2 not generated",
            "final_llm3_evaluation_correct": final_llm3_evaluation_correct,
            "final_llm3_feedback": final_llm3_feedback,

            "llm1_strategy_history": llm1_strategy_history,
            "llm2_repaired_code_history": llm2_repaired_code_history,
            "llm3_evaluation_history": llm3_evaluation_history,
            "status": status
        }
        if current_row_failed:
            result_item["error"] = "Processing failed mid-iteration."
            if final_llm1_strategy_raw == "N/A" and llm1_strategy_history and isinstance(llm1_strategy_history[-1], str):
                result_item["error"] = f"LLM1 failed: {llm1_strategy_history[-1]}"
            elif final_llm2_repaired_code == "N/A" and llm2_repaired_code_history and isinstance(llm2_repaired_code_history[-1], str):
                result_item["error"] = f"LLM2 failed: {llm2_repaired_code_history[-1]}"

        return result_item

    except KeyError as e:
        logger.error(f"Row {original_row_index + 1}: KeyError occurred during processing - column '{e}' not found.")
        return {
            "original_row_index": original_row_index + 1, "error": f"KeyError: {e}",
            "cwe_type": row.get('cwe_type', 'N/A'), "cve_id": row.get('cve_id', 'N/A'),
            "code_before": row.get('code_before', 'N/A'), "code_after_ground_truth": row.get('code_after', 'N/A'),
            "status": "failed"
        }
    except Exception as e:
        logger.error(f"Row {original_row_index + 1}: Unexpected error occurred during processing: {e}", exc_info=True)
        return {
            "original_row_index": original_row_index + 1, "error": str(e),
            "cwe_type": row.get('cwe_type', 'N/A'), "cve_id": row.get('cve_id', 'N/A'),
            "code_before": row.get('code_before', 'N/A'), "code_after_ground_truth": row.get('code_after', 'N/A'),
            "max_iterations_configured": max_iterations,
            "iterations_taken": current_iteration if 'current_iteration' in locals() else 0,
            "llm3_evaluation_history": llm3_evaluation_history if 'llm3_evaluation_history' in locals() else [],
            "status": "failed"
        }


def process_csv_and_analyze_strategy(csv_file_path: str, output_base_dir: str, openai_api_params: dict = None,
                                     max_iterations: int = 1, verbose: bool = False,
                                     num_workers: int = None, log_file: str = None):

    csv.field_size_limit(10000000)

    logger = logging.getLogger(__name__ + "_strategy_analyzer")
    logger.handlers = []
    logger.propagate = False

    if verbose:
        log_level = logging.INFO
        actual_log_file = log_file if log_file else os.path.join(output_base_dir, "strategy_analysis_details.log")
        os.makedirs(os.path.dirname(actual_log_file), exist_ok=True)

        file_handler = logging.FileHandler(actual_log_file, mode='w', encoding='utf-8')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - TID %(thread)d - %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        logger.setLevel(log_level)
        print(f"Detailed log will be output to: {actual_log_file}")
    else:
        logger.addHandler(logging.NullHandler())
        logger.setLevel(logging.WARNING)

    logger.info(f"Starting to process CSV file: {csv_file_path} (max iterations: {max_iterations})")
    logger.info(f"Results will be output to directory: {output_base_dir}")
    print(f"Starting to process CSV file: {csv_file_path}")

    if not os.path.exists(csv_file_path):
        logger.error(f"Error: CSV file not found - {csv_file_path}")
        print(f"Error: CSV file not found - {csv_file_path}")
        return False

    os.makedirs(output_base_dir, exist_ok=True)
    output_json_path = os.path.join(output_base_dir, "strategy_analysis_output.json")
    output_summary_json_path = os.path.join(output_base_dir, "strategy_analysis_summary_output.json")

    results_list = []

    actual_num_workers = num_workers if num_workers is not None and num_workers > 0 else os.cpu_count()
    logger.info(f"Using {actual_num_workers} worker threads for parallel processing.")
    print(f"Using {actual_num_workers} worker threads for parallel processing.")

    all_rows_with_indices = []
    try:
        with open(csv_file_path, mode='r', encoding='utf-8-sig') as file:
            reader = csv.DictReader(file)
            if not reader.fieldnames:
                logger.error(f"Error: CSV file {csv_file_path} is empty or headers cannot be read.")
                print(f"Error: CSV file {csv_file_path} is empty or headers cannot be read.")
                return False

            logger.info(f"CSV headers: {reader.fieldnames}")
            required_columns = ['code_before', 'code_after', 'cwe_type', 'cve_id']
            for col in required_columns:
                if col not in reader.fieldnames:
                    logger.error(f"Error: CSV file is missing required column '{col}'. Please ensure CSV contains {required_columns} columns.")
                    print(f"Error: CSV file is missing required column '{col}'. Please ensure CSV contains {required_columns} columns.")
                    return False
            all_rows_with_indices = list(enumerate(reader))
            print(f"Total {len(all_rows_with_indices)} rows read for processing.")
            logger.info(f"Total {len(all_rows_with_indices)} rows read for processing.")

    except FileNotFoundError:
        logger.error(f"Error: CSV file {csv_file_path} not found.")
        print(f"Error: CSV file {csv_file_path} not found.")
        return False
    except Exception as e:
        logger.error(f"Error: An error occurred while reading or processing CSV file {csv_file_path}: {e}", exc_info=True)
        print(f"Error: An error occurred while reading or processing CSV file {csv_file_path}: {e}")
        return False

    if not all_rows_with_indices:
        print("No data rows in CSV file to process.")
        logger.warning("No data rows in CSV file to process.")
        return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=actual_num_workers) as executor:

        futures_to_rows = {
            executor.submit(_process_row, row_tuple, openai_api_params, max_iterations, logger): row_tuple
            for row_tuple in all_rows_with_indices
        }

        with tqdm(total=len(all_rows_with_indices), desc="Processing CSV rows", unit="row") as pbar:
            for future in concurrent.futures.as_completed(futures_to_rows):
                row_tuple_original = futures_to_rows[future]
                try:
                    result = future.result()
                    results_list.append(result)
                except Exception as exc:
                    original_idx, original_r = row_tuple_original
                    logger.error(f"Row {original_idx + 1} generated exception during execution: {exc}", exc_info=True)
                    results_list.append({
                        "original_row_index": original_idx + 1, "error": f"Unhandled exception in thread: {exc}",
                        "cwe_type": original_r.get('cwe_type', 'N/A'), "cve_id": original_r.get('cve_id', 'N/A'),
                        "code_before": original_r.get('code_before', 'N/A'), "code_after_ground_truth": original_r.get('code_after', 'N/A'),
                        "status": "failed_exception_in_thread"
                    })
                finally:

                    pbar.update(1)

    results_list.sort(key=lambda x: x.get("original_row_index", float('inf')))

    processed_rows = sum(1 for r in results_list if r.get("status") == "success" and "error" not in r)
    failed_rows = len(results_list) - processed_rows

    logger.info(f"All rows processing completed. Success: {processed_rows}, Failed/Skipped: {failed_rows}")
    print(f"All rows processing completed. Success: {processed_rows}, Failed/Skipped: {failed_rows}")

    if results_list:
        summary_results_list = []
        summary_keys_to_include = [
            "original_row_index", "cwe_type", "cve_id", "code_before", "code_after_ground_truth",

            "llm1a_raw_output",

            "candidate_line_numbers_for_slice",


            "sliced_code_before_initial",
            "max_iterations_configured", "iterations_attempted",


            "final_llm1_strategy_raw",
            "final_llm1_precise_source",
            "final_llm1_precise_sink",
            "final_llm1_vulnerability_path",
            "final_llm1_cwe_specific_strategy",
            "final_llm1_pre_repair_state",
            "final_llm1_abstract_strategy",
            "final_llm1_concrete_strategy",
            "final_llm1_post_repair_state",
            "final_llm1_parsing_status",

            "final_llm2_generated_patch",
            "final_llm3_evaluation_correct",
            "final_llm3_feedback",
            "error",
            "status"
        ]

        for item in results_list:
            summary_item = {key: item.get(key, "N/A_in_summary") for key in summary_keys_to_include}
            summary_results_list.append(summary_item)

        try:
            output_dir = os.path.dirname(output_json_path)
            os.makedirs(output_dir, exist_ok=True)

            with open(output_json_path, mode='w', encoding='utf-8') as outfile:
                json.dump(results_list, outfile, indent=4, ensure_ascii=False)
            logger.info(f"Complete processing results saved to: {output_json_path}")
            print(f"Complete processing results saved to: {output_json_path}")

            if summary_results_list:
                with open(output_summary_json_path, mode='w', encoding='utf-8') as outfile_summary:
                    json.dump(summary_results_list, outfile_summary, indent=4, ensure_ascii=False)
                logger.info(f"Summary processing results saved to: {output_summary_json_path}")
                print(f"Summary processing results saved to: {output_summary_json_path}")
            else:
                logger.warning(f"No summary information to write to: {output_summary_json_path}")
                print(f"No summary information to write to: {output_summary_json_path}")

            return True

        except Exception as e:
            logger.error(f"Error: An error occurred while writing JSON file: {e}", exc_info=True)
            print(f"Error: An error occurred while writing JSON file: {e}")
            return False
    else:
        logger.warning("No results to write to JSON file.")
        print("No results to write to JSON file.")
        if processed_rows == 0 and failed_rows > 0:
            logger.warning("All rows failed or were skipped during processing.")
            print("All rows failed or were skipped during processing.")
        return False


if __name__ == '__main__':

    csv.field_size_limit(10000000)

    dataset_name = "manual_example"
    sample_csv_path = f"datasets/{dataset_name}/processed_vulnerabilities.csv"
    output_csv_path = sample_csv_path.replace('.csv', '_final.csv')
    add_headers_and_ids_to_csv(
        input_csv_path=sample_csv_path,
        output_csv_path=output_csv_path,
        headers=['code_before', 'code_after', 'cwe_type', 'cve_id'],
        id_column_name='id',
        id_prefix=''
    )

    try:
        user_openai_params = {"model_ckpt": "<your-model-name>", "temperature": 0.0}
        base_output_dir = f"datasets/{dataset_name}/outputs"
        os.makedirs(base_output_dir, exist_ok=True)

        output_dir_verbose = f"{base_output_dir}/strategy_analysis_verbose"
        log_file_verbose = os.path.join(output_dir_verbose, 'detailed_run.log')
        print(f"\n# Calling process_csv_and_analyze_strategy for processing (parallel, verbose=True, log_file='{log_file_verbose}')...")
        success_verbose = process_csv_and_analyze_strategy(
            csv_file_path=output_csv_path,
            output_base_dir=output_dir_verbose,
            openai_api_params=user_openai_params,
            max_iterations=2,
            verbose=True,
            num_workers=64,
            log_file=log_file_verbose
        )
        if success_verbose:
            print(f"\nDetailed mode parallel processing succeeded. Check {os.path.join(output_dir_verbose, 'strategy_analysis_output.json')} and log {log_file_verbose}.")
        else:
            print("\nDetailed mode parallel processing failed.")

    except Exception as e:
        print(f"\nError: An unexpected error occurred while running example: {e}", exc_info=True)
