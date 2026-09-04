import subprocess
import tempfile
import re
import os
from typing import List, Tuple, Set
from slicer.parse_joern_output2 import slice_code_from_string

def slice_code_from_string(source_code: str, target_lines: list[int], slice_type: str = "backward", data_flow_only: bool = False, verbose: bool = False, visualization_output_dir: str = None) -> str:
    print("Error: slice_code_from_string was not successfully imported. Returning empty string.")
    return ""

def _get_lines_from_string(code_string: str) -> Tuple[List[str], int]:
    if not code_string:
        return [], 0
    lines = code_string.splitlines(keepends=True)
    return lines, len(lines)

def parse_diff_output(diff_text: str, total_old_lines: int, total_new_lines: int) -> Tuple[List[int], List[int], List[int], List[Tuple[int, int]]]:
    modified_lines_old: Set[int] = set()
    deleted_lines_old: Set[int] = set()
    added_lines_new: Set[int] = set()

    hunks_info: List[Tuple[int, int, int, int]] = []
    hunk_header_regex = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

    lines = diff_text.splitlines()
    for line in lines:
        match = hunk_header_regex.match(line)
        if match:
            old_start = int(match.group(1))
            old_len = int(match.group(2)) if match.group(2) is not None else 1
            new_start = int(match.group(3))
            new_len = int(match.group(4)) if match.group(4) is not None else 1

            hunks_info.append((old_start, old_len, new_start, new_len))

            if old_len > 0 and new_len > 0:
                for i in range(old_len):
                    modified_lines_old.add(old_start + i)
                for i in range(new_len):
                    added_lines_new.add(new_start + i)
            elif old_len > 0 and new_len == 0:
                for i in range(old_len):
                    deleted_lines_old.add(old_start + i)
            elif old_len == 0 and new_len > 0:
                for i in range(new_len):
                    added_lines_new.add(new_start + i)

    unchanged_mapping: List[Tuple[int, int]] = []
    hunks_info.sort(key=lambda h: (h[0], h[2]))

    current_old_line = 1
    current_new_line = 1
    hunk_idx = 0

    while current_old_line <= total_old_lines or current_new_line <= total_new_lines:
        processed_by_hunk_logic = False
        if hunk_idx < len(hunks_info):
            h_old_s, h_old_l, h_new_s, h_new_l = hunks_info[hunk_idx]

            if h_old_l == 0:
                while current_new_line < h_new_s:
                    if current_old_line <= total_old_lines:
                         unchanged_mapping.append((current_old_line, current_new_line))
                         current_old_line += 1
                    current_new_line += 1

                current_new_line = h_new_s + h_new_l
                hunk_idx += 1
                processed_by_hunk_logic = True
            elif current_old_line >= h_old_s and current_old_line < (h_old_s + h_old_l):
                current_old_line = h_old_s + h_old_l
                current_new_line = h_new_s + h_new_l
                hunk_idx += 1
                processed_by_hunk_logic = True

        if not processed_by_hunk_logic:
            if current_old_line <= total_old_lines and current_new_line <= total_new_lines:
                unchanged_mapping.append((current_old_line, current_new_line))
                current_old_line += 1
                current_new_line += 1
            elif current_old_line <= total_old_lines:
                current_old_line += 1
            elif current_new_line <= total_new_lines:
                current_new_line += 1
            else:
                break

    return sorted(list(modified_lines_old)), sorted(list(deleted_lines_old)), sorted(list(added_lines_new)), unchanged_mapping

def analyze_code_diff(old_code_str: str, new_code_str: str) -> Tuple[List[int], List[int]]:
    old_code_lines, total_old_lines = _get_lines_from_string(old_code_str)
    new_code_lines, total_new_lines = _get_lines_from_string(new_code_str)

    if not old_code_str and not new_code_str:
        return [], []
    if not old_code_str:
        return [], list(range(1, total_new_lines + 1))
    if not new_code_str:
        return list(range(1, total_old_lines + 1)), []

    diff_text = None
    tmp_old_file_path = None
    tmp_new_file_path = None

    try:


        with tempfile.NamedTemporaryFile(mode='w+', delete=False, encoding='utf-8', prefix="old_", suffix=".tmp", newline='') as tmp_old_file, \
             tempfile.NamedTemporaryFile(mode='w+', delete=False, encoding='utf-8', prefix="new_", suffix=".tmp", newline='') as tmp_new_file:

            tmp_old_file.writelines(old_code_lines)
            tmp_old_file_path = tmp_old_file.name
            tmp_old_file.flush()

            tmp_new_file.writelines(new_code_lines)
            tmp_new_file_path = tmp_new_file.name
            tmp_new_file.flush()


        cmd = ["git", "diff", "--no-index", "-U0", tmp_old_file_path, tmp_new_file_path]
        process = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', check=False)


        if process.returncode > 1:
            print(f"git diff command execution error (return code {process.returncode}):\n{process.stderr}")
            return [], []
        diff_text = process.stdout

    finally:

        for tmp_path in [tmp_old_file_path, tmp_new_file_path]:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError as e:
                    print(f"Warning: Failed to delete temporary file {tmp_path}: {e}")

    if diff_text is None:

        print("Failed to get diff output.")
        return [], []


    if not diff_text.strip():

        return [], []

    modified_old, deleted_old, added_new, _ = parse_diff_output(diff_text, total_old_lines, total_new_lines)

    changed_or_deleted_lines_old = sorted(list(set(modified_old) | set(deleted_old)))

    added_or_modified_lines_new = added_new

    return changed_or_deleted_lines_old, added_or_modified_lines_new


def process_code_changes(old_code_str: str, new_code_str: str) -> Tuple[str, str]:
    changed_or_deleted_lines_old, added_or_modified_lines_new = analyze_code_diff(old_code_str, new_code_str)

    sliced_old_code = ""
    if changed_or_deleted_lines_old:
        try:
            sliced_old_code,_ = slice_code_from_string(
                source_code=old_code_str,
                target_lines=changed_or_deleted_lines_old,
                slice_type="backward",
                data_flow_only=False,
                verbose=False
            )
        except Exception as e:
            print(f"  Error occurred during old code slicing: {e}")


    sliced_new_code = ""
    if added_or_modified_lines_new:
        try:
            sliced_new_code,_ = slice_code_from_string(
                source_code=new_code_str,
                target_lines=added_or_modified_lines_new,
                slice_type="backward",
                data_flow_only=False,
                verbose=False
            )
        except Exception as e:
            print(f"  Error occurred during new code slicing: {e}")

    return sliced_old_code, sliced_new_code
