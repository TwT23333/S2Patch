import os
import sys
import argparse
import json
import shutil
import subprocess
import pandas as pd
import numpy as np
from scipy import sparse
from collections import defaultdict
from graphviz import Digraph
import tempfile
import uuid
from pathlib import Path
import networkx as nx

def rdg(edges, gtype):

    if 'etype' not in edges.columns:

        return pd.DataFrame(columns=edges.columns)

    if gtype == "reftype":
        return edges[(edges.etype == "EVAL_TYPE") | (edges.etype == "REF")]
    if gtype == "ast":
        return edges[(edges.etype == "AST")]
    if gtype == "pdg":
        return edges[(edges.etype == "REACHING_DEF") | (edges.etype == "CDG")]
    if gtype == "ddg":
        return edges[(edges.etype == "REACHING_DEF")]
    if gtype == "cfgddg":
        return edges[(edges.etype == "REACHING_DEF") | (edges.etype == "CFG")]
    if gtype == "cfgcdg":
        return edges[(edges.etype == "CFG") | (edges.etype == "CDG")]
    if gtype == "all":
        return edges[
            (edges.etype == "REACHING_DEF")
            | (edges.etype == "CDG")
            | (edges.etype == "AST")

            | (edges.etype == "EVAL_TYPE")
            | (edges.etype == "REF")
            | (edges.etype == "CFG")
        ]
    return pd.DataFrame(columns=edges.columns)


def neighbour_nodes(nodes, edges, nodeids: list, hop: int = 1, intermediate=True):
    if 'id' not in nodes.columns:

        return defaultdict(list)
    if 'innode' not in edges.columns or 'outnode' not in edges.columns:

        return defaultdict(list)


    node_id_set = set(nodes['id'].unique())
    valid_nodeids = [nid for nid in nodeids if nid in node_id_set]

    if not valid_nodeids or edges.empty:
        return defaultdict(list)

    nodes_new = nodes.reset_index(drop=True).reset_index().rename(columns={"index": "adj"})
    id2adj = pd.Series(nodes_new.adj.values, index=nodes_new.id).to_dict()
    adj2id = {v: k for k, v in id2adj.items()}

    arr = []

    valid_edges = edges[edges['innode'].isin(id2adj.keys()) & edges['outnode'].isin(id2adj.keys())]

    for e_in, e_out in zip(valid_edges.innode.map(id2adj), valid_edges.outnode.map(id2adj)):
        if pd.notna(e_in) and pd.notna(e_out):
            arr.append([int(e_in), int(e_out)])
            arr.append([int(e_out), int(e_in)])

    if not arr:
        return defaultdict(list)

    arr = np.array(arr)

    max_idx_val = arr.max()
    graph_shape = (max_idx_val + 1, max_idx_val + 1)

    coo = sparse.coo_matrix((np.ones(len(arr)), (arr[:, 0], arr[:, 1])), shape=graph_shape)
    base_csr = coo.tocsr()
    neighbours = defaultdict(list)

    def get_neighbors_from_powered_csr(current_node_id, powered_csr_matrix):
        if current_node_id not in id2adj: return []
        adj_idx = id2adj[current_node_id]
        if adj_idx >= powered_csr_matrix.shape[0]: return []

        neighbor_adj_indices = powered_csr_matrix[adj_idx].nonzero()[1]
        return [adj2id[i] for i in neighbor_adj_indices if i in adj2id]

    if intermediate:
        for h_iter in range(1, hop + 1):
            if h_iter == 0: continue
            powered_csr = base_csr ** h_iter
            for nodeid_item in valid_nodeids:
                current_neighbors = get_neighbors_from_powered_csr(nodeid_item, powered_csr)
                neighbours[nodeid_item].extend(current_neighbors)
    else:
        if hop > 0:
            powered_csr = base_csr ** hop
            for nodeid_item in valid_nodeids:
                current_neighbors = get_neighbors_from_powered_csr(nodeid_item, powered_csr)
                neighbours[nodeid_item].extend(current_neighbors)


    for nodeid_item in list(neighbours.keys()):
        if neighbours[nodeid_item]:
             neighbours[nodeid_item] = sorted(list(set(neighbours[nodeid_item])))
        else:
            del neighbours[nodeid_item]

    return neighbours


def assign_line_num_to_local(nodes_df_input, edges_df_input, code_lines_list):
    nodes_df = nodes_df_input.copy()
    edges_df = edges_df_input.copy()

    required_node_cols = ['id', '_label', 'name', 'lineNumber']
    required_edge_cols = ['innode', 'outnode', 'etype']
    if not all(col in nodes_df.columns for col in required_node_cols):

        return {}
    if not all(col in edges_df.columns for col in required_edge_cols):

        return {}

    label_nodes = nodes_df[nodes_df['_label'] == "LOCAL"]['id'].tolist()
    if not label_nodes:
        return {}


    ast_edges = rdg(edges_df, "ast")
    onehop_labels = neighbour_nodes(nodes_df, ast_edges, label_nodes, hop=1, intermediate=False)


    reftype_edges = rdg(edges_df, "reftype")
    twohop_labels = neighbour_nodes(nodes_df, reftype_edges, label_nodes, hop=2, intermediate=False)

    node_types_df = nodes_df[nodes_df['_label'] == "TYPE"]
    if 'name' not in node_types_df.columns: node_types_df['name'] = ''
    id2name = pd.Series(node_types_df.name.values, index=node_types_df.id).to_dict()

    node_blocks_df = nodes_df[(nodes_df['_label'] == "BLOCK") | (nodes_df['_label'] == "CONTROL_STRUCTURE")]


    blocknode2line = pd.Series(node_blocks_df.lineNumber.values, index=node_blocks_df.id).dropna().to_dict()

    local_vars_type_name = {}
    local_vars_block_line = {}

    for local_node_id, type_node_candidates in twohop_labels.items():
        actual_type_node_ids = [tn_id for tn_id in type_node_candidates if tn_id in id2name]
        if not actual_type_node_ids: continue
        var_type_name = id2name[actual_type_node_ids[0]]

        if local_node_id not in onehop_labels or not onehop_labels[local_node_id]: continue
        block_node_candidates = onehop_labels[local_node_id]


        actual_block_node_id = None
        block_line_num = pd.NA
        for bn_id in block_node_candidates:
            if bn_id in blocknode2line and pd.notna(blocknode2line[bn_id]):
                actual_block_node_id = bn_id
                block_line_num = blocknode2line[actual_block_node_id]
                break

        if pd.isna(block_line_num): continue

        local_vars_type_name[local_node_id] = var_type_name
        local_vars_block_line[local_node_id] = block_line_num

    nodes_df["local_var_type_name"] = nodes_df['id'].map(local_vars_type_name)
    nodes_df["local_var_block_line"] = nodes_df['id'].map(local_vars_block_line)

    local_line_map_final = {}


    if 'name' not in nodes_df.columns: nodes_df['name'] = ''

    relevant_locals_df = nodes_df[
        (nodes_df['_label'] == "LOCAL") &
        nodes_df['local_var_type_name'].notna() &
        nodes_df['local_var_block_line'].notna() &
        nodes_df['name'].notna()
    ].copy()

    for _, row in relevant_locals_df.iterrows():
        var_name = str(row['name'])
        var_type = str(row['local_var_type_name'])
        block_start_line_1based = int(row['local_var_block_line'])


        normalized_type = "".join(var_type.split())
        normalized_name = "".join(var_name.split())


        search_patterns = [
            f"{normalized_type}{normalized_name};",
            f"{var_type.strip()} {var_name.strip()};"
        ]


        found_line_1based = pd.NA

        search_from_idx_0based = block_start_line_1based - 1
        if search_from_idx_0based < 0: search_from_idx_0based = 0

        for line_idx_0based in range(search_from_idx_0based, len(code_lines_list)):
            code_line_content = code_lines_list[line_idx_0based]
            normalized_code_line = "".join(code_line_content.split())

            match_found = False
            for pattern in search_patterns:
                normalized_pattern = "".join(pattern.split())
                if normalized_pattern in normalized_code_line:


                    if normalized_code_line.startswith(normalized_pattern.replace(";", "")):
                         match_found = True
                         break


                    if normalized_pattern == normalized_code_line:
                        match_found = True
                        break


            if match_found:
                found_line_1based = line_idx_0based + 1
                break

        if pd.notna(found_line_1based):
            local_line_map_final[row['id']] = found_line_1based

    return local_line_map_final

def read_json_file(json_file_path):
    with open(json_file_path, 'r') as f:
        data = json.load(f)
    return data


def read_code_file(file_path):
    code_lines = {}
    with open(file_path) as fp:
        for ln, line in enumerate(fp):
            assert isinstance(line, str)
            line = line.strip()
            if '//' in line:
                line = line[:line.index('//')]
            code_lines[ln + 1] = line
        return code_lines


def extract_nodes_with_location_info(nodes_df_from_csv, edges_df_renamed_for_assign, raw_code_lines_for_assign):
    if nodes_df_from_csv.empty:
        return pd.DataFrame(), [], [], {}, {}

    nodes_df = nodes_df_from_csv.copy()


    column_map_for_nodes = {}

    if 'key' in nodes_df.columns:
        column_map_for_nodes['key'] = 'id'
    if 'type' in nodes_df.columns:
        column_map_for_nodes['type'] = '_label'
    if 'identifier' in nodes_df.columns:
        column_map_for_nodes['identifier'] = 'name'


    nodes_df = nodes_df.rename(columns=column_map_for_nodes)


    if 'id' in nodes_df.columns:
        nodes_df['id'] = nodes_df['id'].astype(str)
    else:
        nodes_df['id'] = pd.Series(range(len(nodes_df))).astype(str)


    if 'code' not in nodes_df.columns and 'CODE' in nodes_df.columns:
        nodes_df.rename(columns={'CODE': 'code'}, inplace=True)
    if 'code' not in nodes_df.columns:
        nodes_df['code'] = ''


    if '_label' not in nodes_df.columns:
        nodes_df['_label'] = ''


    if 'name' not in nodes_df.columns:
        nodes_df['name'] = ''

    for col_ensure in ['id', '_label', 'name', 'lineNumber', 'code']:
        if col_ensure not in nodes_df.columns:
            if col_ensure == 'lineNumber':
                 nodes_df[col_ensure] = pd.NA
            else:
                 nodes_df[col_ensure] = ''


    if 'lineNumber' in nodes_df.columns and nodes_df['lineNumber'].notna().any():
        nodes_df['lineNumber'] = pd.to_numeric(nodes_df['lineNumber'], errors='coerce')
    elif 'LINE_NUMBER' in nodes_df.columns:
        nodes_df['lineNumber'] = pd.to_numeric(nodes_df['LINE_NUMBER'], errors='coerce')
        if 'LINE_NUMBER' != 'lineNumber': nodes_df = nodes_df.drop(columns=['LINE_NUMBER'], errors='ignore')
    elif 'location' in nodes_df.columns:
        def get_ln_from_loc(location_str):
            if not location_str or not isinstance(location_str, str) or ':' not in location_str:
                return pd.NA
            try:
                line_part = location_str.split(':')[0]
                return int(line_part) if line_part else pd.NA
            except (ValueError, AttributeError):
                return pd.NA
        nodes_df['lineNumber'] = nodes_df['location'].apply(get_ln_from_loc)
    else:
        nodes_df['lineNumber'] = pd.NA

    if 'controlStructureType' not in nodes_df.columns:
        nodes_df['controlStructureType'] = ""

    nodes_df_for_assign = nodes_df.copy()
    edges_df_for_assign = edges_df_renamed_for_assign.copy()

    local_line_map = assign_line_num_to_local(
        nodes_df_for_assign,
        edges_df_for_assign,
        raw_code_lines_for_assign
    )

    for node_id_key, refined_ln in local_line_map.items():

        nodes_df.loc[nodes_df['id'] == node_id_key, 'lineNumber'] = refined_ln


    node_indices_return = []
    node_ids_return = []
    line_numbers_return = []
    node_id_to_line_number_return = {}

    for idx, row in nodes_df.iterrows():
        node_id_val = str(row['id'])
        line_num_val = row['lineNumber']

        if pd.notna(line_num_val):
            try:
                line_num_int = int(line_num_val)
                if line_num_int <= 0:
                    continue


                node_indices_return.append(idx)
                node_ids_return.append(node_id_val)
                line_numbers_return.append(line_num_int)
                node_id_to_line_number_return[node_id_val] = line_num_int
            except ValueError:

                continue


    unique_sorted_line_numbers = sorted(list(set(line_numbers_return)))

    return nodes_df, node_indices_return, node_ids_return, unique_sorted_line_numbers, node_id_to_line_number_return

def create_node_level_graph(nodes_df, edges_df, relevant_edge_types):
    node_graph = defaultdict(set)


    for _, edge in edges_df.iterrows():
        edge_type = edge.get('etype')


        try:

            innode_id = int(edge['innode'])
            outnode_id = int(edge['outnode'])
        except (ValueError, TypeError, KeyError):

            continue

        if edge_type in relevant_edge_types:
            node_graph[innode_id].add(outnode_id)

    return node_graph

def invert_node_graph(graph):
    inverted_graph = defaultdict(set)
    for source_node, dependent_nodes in graph.items():
        for dependent_node in dependent_nodes:
            inverted_graph[dependent_node].add(source_node)
    return inverted_graph

def perform_node_level_slice(graph, start_node_ids):
    if not start_node_ids:
        return set()


    sliced_node_ids = set()
    queue = []

    for nid in start_node_ids:
        if nid not in sliced_node_ids:
            sliced_node_ids.add(nid)
            queue.append(nid)

    head = 0
    while head < len(queue):
        current_node_id = queue[head]
        head += 1


        if current_node_id in graph:
            for neighbor_node_id in graph[current_node_id]:
                if neighbor_node_id not in sliced_node_ids:
                    sliced_node_ids.add(neighbor_node_id)
                    queue.append(neighbor_node_id)
    return sliced_node_ids

def get_ast_parent_info(node_id_str, nodes_df, edges_df):
    try:
        node_id_int = int(node_id_str)
    except ValueError:
        return None, None

    parent_edges = edges_df[(edges_df['outnode'] == node_id_int) & (edges_df['etype'] == 'IS_AST_PARENT')]
    if not parent_edges.empty:
        parent_id_int = parent_edges.iloc[0]['innode']
        parent_id_str = str(parent_id_int)
        parent_node_series_rows = nodes_df[nodes_df['id'] == parent_id_str]
        if not parent_node_series_rows.empty:
            return parent_id_str, parent_node_series_rows.iloc[0]
    return None, None

def get_effective_call_site_line(start_node_id_str, nodes_df, edges_df, node_id_to_ln_map, verbose_output=False, max_depth=10):
    current_node_id_str = start_node_id_str
    current_node_series = nodes_df[nodes_df['id'] == current_node_id_str].iloc[0] if not nodes_df[nodes_df['id'] == current_node_id_str].empty else None

    for _ in range(max_depth):
        if current_node_series is None:
            if verbose_output: print(f"  get_effective_call_site_line: Node {current_node_id_str} not found in nodes_df.")
            return None

        line_num = node_id_to_ln_map.get(current_node_id_str)
        if line_num is not None:


            return line_num

        parent_id_str, parent_node_series = get_ast_parent_info(current_node_id_str, nodes_df, edges_df)
        if parent_id_str is None:
            if verbose_output: print(f"  get_effective_call_site_line: No AST parent found for {current_node_id_str}. Using its own (missing) line number.")
            return None

        current_node_id_str = parent_id_str
        current_node_series = parent_node_series


    if verbose_output: print(f"  get_effective_call_site_line: Max depth reached for {start_node_id_str}, line number not found.")
    return None


def get_ast_children_sorted(parent_node_id_str, child_label_filter, nodes_df, edges_df, node_id_to_line_numbers, sort_key='childNum'):
    children_info = []
    try:
        parent_node_id_int = int(parent_node_id_str)
    except ValueError:

        return []


    ast_child_edges = edges_df[(edges_df['innode'] == parent_node_id_int) & (edges_df['etype'] == 'IS_AST_PARENT')]

    for _, edge in ast_child_edges.iterrows():
        child_node_id_int = edge['outnode']
        child_node_id_str = str(child_node_id_int)

        child_node_details_rows = nodes_df[nodes_df['id'] == child_node_id_str]
        if not child_node_details_rows.empty:
            child_node_details = child_node_details_rows.iloc[0]
            if child_label_filter is None or child_node_details.get('_label') == child_label_filter:
                child_info = {
                    'id': child_node_id_str,
                    'line': node_id_to_line_numbers.get(child_node_id_str),
                    'code': child_node_details.get('code'),
                    sort_key: int(child_node_details.get(sort_key, -1)),
                    '_label': child_node_details.get('_label'),
                    'name': child_node_details.get('name')
                }
                children_info.append(child_info)

    children_info.sort(key=lambda x: x[sort_key])
    return children_info

def create_adjacency_list(line_numbers, node_id_to_line_numbers, nodes_df, edges_df,
                          function_name_to_definition_map, data_dependency_only=False, verbose_output=False):
    adjacency_list = {}
    all_lines_in_scope = set(line_numbers)


    encountered_edge_types = set()


    for ln_init in set(line_numbers):
        adjacency_list[ln_init] = [set(), set()]


    for edge_row in edges_df.itertuples(index=False):

        if not (hasattr(edge_row, 'innode') and hasattr(edge_row, 'outnode')):

            continue

        start_node_id_str = str(edge_row.innode).strip()
        end_node_id_str = str(edge_row.outnode).strip()

        if start_node_id_str in node_id_to_line_numbers and end_node_id_str in node_id_to_line_numbers:
            start_ln = node_id_to_line_numbers[start_node_id_str]
            end_ln = node_id_to_line_numbers[end_node_id_str]
            if start_ln not in adjacency_list:
                adjacency_list[start_ln] = [set(), set()]
            if end_ln not in adjacency_list:
                adjacency_list[end_ln] = [set(), set()]
            all_lines_in_scope.add(start_ln)
            all_lines_in_scope.add(end_ln)


    for ln_scope in all_lines_in_scope:
        if ln_scope not in adjacency_list:
            adjacency_list[ln_scope] = [set(), set()]


    for edge_row in edges_df.itertuples(index=False):
        if not (hasattr(edge_row, 'innode') and hasattr(edge_row, 'outnode') and hasattr(edge_row, 'etype')):
            continue

        edge_type_str = str(edge_row.etype).strip()
        encountered_edge_types.add(edge_type_str)
        start_node_id_str = str(edge_row.innode).strip()
        end_node_id_str = str(edge_row.outnode).strip()

        if start_node_id_str not in node_id_to_line_numbers or end_node_id_str not in node_id_to_line_numbers:
            continue

        start_ln = node_id_to_line_numbers[start_node_id_str]
        end_ln = node_id_to_line_numbers[end_node_id_str]

        if start_ln not in adjacency_list: adjacency_list[start_ln] = [set(), set()]
        if end_ln not in adjacency_list: adjacency_list[end_ln] = [set(), set()]

        if not data_dependency_only:
            if edge_type_str == 'FLOWS_TO':
                adjacency_list[start_ln][0].add(end_ln)

        if edge_type_str == 'REACHES':
            adjacency_list[start_ln][1].add(end_ln)

    if not nodes_df.empty:
        call_expression_nodes = nodes_df[nodes_df['_label'] == 'CallExpression']
        if verbose_output:
            print(f"Found {len(call_expression_nodes)} 'CallExpression' nodes for inter-procedural analysis.")

        for _, call_expr_node in call_expression_nodes.iterrows():
            call_expr_node_id_str = str(call_expr_node['id'])
            call_site_line_num = get_effective_call_site_line(call_expr_node_id_str, nodes_df, edges_df, node_id_to_line_numbers, verbose_output)

            if call_site_line_num is None:
                if verbose_output: print(f"Skipping CallExpression node {call_expr_node_id_str} (original code: '{call_expr_node.get('code', '')[:30]}...') due to missing effective line number.")
                continue


            callee_nodes_info = get_ast_children_sorted(call_expr_node_id_str, 'Callee', nodes_df, edges_df, node_id_to_line_numbers, sort_key='childNum')
            if not callee_nodes_info or callee_nodes_info[0].get('childNum', -1) != 0:
                if verbose_output: print(f"Callee node not found or not childNum 0 for CallExpression {call_expr_node_id_str} at effective line {call_site_line_num}.")
                continue

            callee_node_info = callee_nodes_info[0]
            called_function_name = callee_node_info.get('code')

            if not called_function_name:
                if verbose_output: print(f"Callee node for CallExpression {call_expr_node_id_str} (effective line {call_site_line_num}) has no function name (code).")
                continue


            function_def_info = function_name_to_definition_map.get(called_function_name)
            if not function_def_info:

                known_library_functions = {"printf", "scanf", "malloc", "free", "strcpy", "strlen", "fprintf", "sprintf", "puts", "gets"}
                if called_function_name in known_library_functions:
                    if verbose_output:
                        print(f"  INFO InterProc: Skipping known library function '{called_function_name}' called at effective line {call_site_line_num}.")
                elif verbose_output:
                    print(f"No definition found for function '{called_function_name}' called at effective line {call_site_line_num}.")
                continue


            func_entry_line_num = function_def_info.get('entry_line')


            if func_entry_line_num is not None and not data_dependency_only:
                if call_site_line_num not in adjacency_list: adjacency_list[call_site_line_num] = [set(), set()]
                adjacency_list[call_site_line_num][0].add(func_entry_line_num)
                if verbose_output:
                    print(f"  DEBUG InterProc: Added CFG Edge: Line {call_site_line_num} -> Line {func_entry_line_num} (Call to {called_function_name})")
                    print(f"    DEBUG InterProc: adjacency_list[{call_site_line_num}] after CFG add: {adjacency_list[call_site_line_num]}")


            actual_arg_wrapper_nodes = []


            arg_list_nodes = get_ast_children_sorted(call_expr_node_id_str, 'ArgumentList', nodes_df, edges_df, node_id_to_line_numbers, sort_key='childNum')

            if arg_list_nodes:


                argument_list_node_id = arg_list_nodes[0]['id']
                actual_arg_wrapper_nodes = get_ast_children_sorted(argument_list_node_id, 'Argument', nodes_df, edges_df, node_id_to_line_numbers, sort_key='childNum')
                if verbose_output:
                    print(f"  Found ArgumentList (ID: {argument_list_node_id}) for CallExpr {call_expr_node_id_str}. It has {len(actual_arg_wrapper_nodes)} Argument children.")
            elif verbose_output:
                print(f"  No ArgumentList child found for CallExpression {call_expr_node_id_str}. No actual arguments will be processed this way.")


            formal_params_from_map = function_def_info.get('formal_params', [])

            if verbose_output:
                print(f"Call to {called_function_name} at effective line {call_site_line_num}: {len(actual_arg_wrapper_nodes)} actual arg wrappers found, {len(formal_params_from_map)} formal params in map.")

            for i, actual_arg_wrapper_info in enumerate(actual_arg_wrapper_nodes):
                if i < len(formal_params_from_map):


                    actual_value_cont_nodes = get_ast_children_sorted(actual_arg_wrapper_info['id'], None, nodes_df, edges_df, node_id_to_line_numbers, sort_key='childNum')

                    if not actual_value_cont_nodes:
                        if verbose_output: print(f"  Actual arg wrapper {actual_arg_wrapper_info['id']} (line {actual_arg_wrapper_info.get('line')}) has no value child.")
                        continue


                    actual_param_node_for_line = actual_value_cont_nodes[0]
                    actual_param_line_num = actual_param_node_for_line.get('line')
                    if actual_param_line_num is None:
                        actual_param_line_num = actual_arg_wrapper_info.get('line')


                    if actual_param_line_num is None:
                        actual_param_line_num = call_site_line_num


                    formal_param_info_from_map = formal_params_from_map[i]
                    formal_param_line_num = formal_param_info_from_map.get('line')
                    if actual_param_line_num is not None and formal_param_line_num is not None:
                        if actual_param_line_num not in adjacency_list: adjacency_list[actual_param_line_num] = [set(), set()]
                        adjacency_list[actual_param_line_num][1].add(formal_param_line_num)
                        if verbose_output:
                            actual_code_repr = actual_param_node_for_line.get('code', actual_arg_wrapper_info.get('code', 'N/A'))
                            print(f"  DEBUG InterProc: Added DDG Edge: Arg {i+1}: Line {actual_param_line_num} (Actual: '{actual_code_repr}') -> Line {formal_param_line_num} (Formal: '{formal_param_info_from_map.get('name')}')")
                            print(f"    DEBUG InterProc: adjacency_list[{actual_param_line_num}] after DDG add: {adjacency_list[actual_param_line_num]}")
                    elif verbose_output:
                        print(f"  Skipping DDG for Arg {i+1} due to missing line number(s): Actual line {actual_param_line_num}, Formal line {formal_param_line_num}")

                elif verbose_output:
                    print(f"  Warning: More actual arguments than formal parameters for call to {called_function_name} at effective line {call_site_line_num}.")
                    break


    if verbose_output:
        print(f"\nDEBUG InterProc: Finished processing all CallExpressions. Final relevant adjacency_list entries:")
        for ce_node in call_expression_nodes.iterrows():
            cs_line = get_effective_call_site_line(str(ce_node[1]['id']), nodes_df, edges_df, node_id_to_line_numbers, False)
            if cs_line and cs_line in adjacency_list:
                 print(f"  adj_list[{cs_line}]: {adjacency_list[cs_line]}")


    if not nodes_df.empty and 'functionId' in nodes_df.columns:
        if verbose_output:
            print("\n--- Processing Inter-procedural Return Value Data Flows ---")


        function_id_to_name_map = {
            details['id']: name for name, details in function_name_to_definition_map.items()
        }

        return_statement_nodes = nodes_df[nodes_df['_label'] == 'ReturnStatement']
        if verbose_output:
            print(f"Found {len(return_statement_nodes)} 'ReturnStatement' nodes.")

        for _, ret_node in return_statement_nodes.iterrows():
            ret_node_id_str = str(ret_node['id'])
            ret_node_line_debug = node_id_to_line_numbers.get(ret_node_id_str, 'N/A_STMT')
            if verbose_output: print(f"\n  DEBUG ReturnProc: Processing ReturnStatement ID {ret_node_id_str} (Line: {ret_node_line_debug})")


            returned_expr_children = get_ast_children_sorted(ret_node_id_str, None, nodes_df, edges_df, node_id_to_line_numbers, sort_key='childNum')

            if not returned_expr_children:
                if verbose_output: print(f"  Skipping ReturnStatement {ret_node_id_str} (line {node_id_to_line_numbers.get(ret_node_id_str, 'N/A')}): No returned expression child.")
                continue

            returned_value_node_info = returned_expr_children[0]
            returned_value_node_id_str = returned_value_node_info['id']

            l_ret_val = node_id_to_line_numbers.get(returned_value_node_id_str)
            if verbose_output: print(f"    DEBUG ReturnProc: Returned value node ID {returned_value_node_id_str}, initial L_ret_val: {l_ret_val}")

            if l_ret_val is None:
                l_ret_val = node_id_to_line_numbers.get(ret_node_id_str)
                if verbose_output: print(f"    DEBUG ReturnProc: Fallback L_ret_val (from stmt itself): {l_ret_val}")

            if l_ret_val is None:
                if verbose_output: print(f"  DEBUG ReturnProc: Skipping ReturnStatement {ret_node_id_str}: Cannot get line for returned value or statement itself.")
                continue
            if verbose_output: print(f"    DEBUG ReturnProc: Final L_ret_val: {l_ret_val}")


            parent_function_node_id_raw_str = str(ret_node.get('functionId', '')).strip()
            if verbose_output: print(f"    DEBUG ReturnProc: Raw parent functionId from ret_node: '{parent_function_node_id_raw_str}'")

            parent_function_node_id_processed = ""
            if parent_function_node_id_raw_str:
                try:

                    parent_function_node_id_processed = str(int(float(parent_function_node_id_raw_str)))
                except ValueError:
                    if verbose_output: print(f"    DEBUG ReturnProc: Could not convert raw functionId '{parent_function_node_id_raw_str}' to int format. Using raw string.")
                    parent_function_node_id_processed = parent_function_node_id_raw_str

            if verbose_output: print(f"    DEBUG ReturnProc: Processed parent function_node_id for map lookup: '{parent_function_node_id_processed}'")

            if not parent_function_node_id_processed or parent_function_node_id_processed not in function_id_to_name_map:
                if verbose_output: print(f"  DEBUG ReturnProc: Skipping ReturnStatement {ret_node_id_str} (L_ret_val: {l_ret_val}): Cannot determine parent function or parent function not in map (processed functionId: '{parent_function_node_id_processed}'). Map keys: {list(function_id_to_name_map.keys())}")
                continue

            parent_function_name = function_id_to_name_map[parent_function_node_id_processed]
            if verbose_output: print(f"    DEBUG ReturnProc: Determined parent function name: '{parent_function_name}'")


            for _, call_expr_node_for_return in call_expression_nodes.iterrows():
                call_expr_id_str_for_return = str(call_expr_node_for_return['id'])

                callee_children_for_return = get_ast_children_sorted(call_expr_id_str_for_return, 'Callee', nodes_df, edges_df, node_id_to_line_numbers, 'childNum')
                if not callee_children_for_return: continue

                called_func_name_at_site = callee_children_for_return[0].get('code')

                if called_func_name_at_site == parent_function_name:
                    if verbose_output: print(f"      DEBUG ReturnProc: Match! Call to '{called_func_name_at_site}' (ID: {call_expr_id_str_for_return}) matches parent func '{parent_function_name}'.")

                    l_call = get_effective_call_site_line(call_expr_id_str_for_return, nodes_df, edges_df, node_id_to_line_numbers, verbose_output=False)
                    if verbose_output: print(f"        DEBUG ReturnProc: Effective call site line L_call: {l_call}")

                    if l_call is not None:
                        if l_ret_val not in adjacency_list: adjacency_list[l_ret_val] = [set(), set()]
                        adjacency_list[l_ret_val][1].add(l_call)
                        if verbose_output:
                            print(f"  DEBUG ReturnFlow: Added DDG Edge: Return in {parent_function_name} (L_ret_val: {l_ret_val}) -> Call site of {called_func_name_at_site} (L_call: {l_call})")
                            print(f"    DEBUG ReturnFlow: adjacency_list[{l_ret_val}] after DDG add: {adjacency_list[l_ret_val]}")
                    elif verbose_output:
                        print(f"  DEBUG ReturnProc: Skipping return flow for call to {called_func_name_at_site} (Return in {parent_function_name} at L_ret_val {l_ret_val}): L_call is None.")


    return adjacency_list


def get_node_attributes(node_row: pd.Series) -> dict:
    return node_row.to_dict()

def get_edge_attributes(edge_row: pd.Series) -> dict:
    attributes = edge_row.to_dict()

    attributes.pop('innode', None)
    attributes.pop('outnode', None)
    return attributes

def build_full_graph_nx(nodes_df: pd.DataFrame, edges_df: pd.DataFrame, graph_edge_types: str) -> nx.DiGraph:
    G = nx.DiGraph()


    if 'id' not in nodes_df.columns:

        pass
    else:
        for _, node_row in nodes_df.iterrows():
            node_id = str(node_row['id'])
            attributes = get_node_attributes(node_row)
            G.add_node(node_id, **attributes)


    include_cfg = 'cfg' in graph_edge_types
    include_ddg = 'ddg' in graph_edge_types


    if not all(col in edges_df.columns for col in ['innode', 'outnode', 'etype']):

        pass
    else:
        for _, edge_row in edges_df.iterrows():
            source_id = str(edge_row['innode'])
            target_id = str(edge_row['outnode'])
            edge_type = edge_row.get('etype', '')

            flow_type_attr = None
            add_this_edge = False

            if include_cfg and edge_type == 'FLOWS_TO':
                add_this_edge = True
                flow_type_attr = 'control'
            elif include_ddg and edge_type == 'REACHES':
                add_this_edge = True
                flow_type_attr = 'data'

            if add_this_edge:
                edge_attrs = get_edge_attributes(edge_row)
                if flow_type_attr:
                    edge_attrs['flow_type'] = flow_type_attr
                G.add_edge(source_id, target_id, **edge_attrs)
    return G

def extract_slice_subgraph_nx(full_program_graph: nx.DiGraph, sliced_node_ids: set[str]) -> nx.DiGraph:
    if not sliced_node_ids:
        return nx.DiGraph()


    valid_node_ids_for_subgraph = [nid for nid in sliced_node_ids if nid in full_program_graph]

    if not valid_node_ids_for_subgraph:
        return nx.DiGraph()

    return full_program_graph.subgraph(valid_node_ids_for_subgraph).copy()


def create_visual_graph(code, adjacency_list, file_name_prefix='test_graph', verbose_render=False):
    graph = Digraph('Code Property Graph Slice View')

    present_lines = set()
    for ln in adjacency_list:
        present_lines.add(ln)
        control_dependency, data_dependency = adjacency_list[ln]
        for anode in control_dependency: present_lines.add(anode)
        for anode in data_dependency: present_lines.add(anode)

    for ln in sorted(list(present_lines)):
        node_label = f"{ln}"
        if ln in code:
            node_label += f"\t{code[ln]}"
        else:
            node_label += "\t(Line not in code map)"
        graph.node(str(ln), node_label, shape='box')

    for ln in adjacency_list:
        control_dependency, data_dependency = adjacency_list[ln]
        for anode in control_dependency:
            graph.edge(str(ln), str(anode), color='red', label='ctrl')
        for anode in data_dependency:
            graph.edge(str(ln), str(anode), color='blue', label='data')

    try:


        rendered_path = graph.render(filename=file_name_prefix, view=False, cleanup=True)
        if verbose_render:
            print(f"Visual graph rendered to {rendered_path}")
    except Exception as e:
        print(f"Warning: Could not render visual graph {file_name_prefix}: {e}")


def create_forward_slice(adjacency_list: dict, slice_lines: set[int]):
    if not slice_lines:
        return []


    graph_nodes = set(adjacency_list.keys())
    for nodes_in_val in adjacency_list.values():
        graph_nodes.update(nodes_in_val)


    if not any(sl in graph_nodes for sl in slice_lines):
        return sorted(list(slice_lines))

    current_slice = set(slice_lines)

    queue = list(slice_lines)


    visited_for_queue = set(slice_lines)

    head = 0
    while head < len(queue):
        cur = queue[head]
        head += 1

        if cur in adjacency_list:
            adjacents_from_cur = adjacency_list.get(cur, set())
            for neighbor_node in adjacents_from_cur:
                if neighbor_node not in current_slice:
                    current_slice.add(neighbor_node)


                    queue.append(neighbor_node)


    return sorted(list(current_slice))


def combine_control_and_data_adjacents(adjacency_list):
    cgraph = {}
    all_lines = set(adjacency_list.keys())
    for ln_key, (ctrl_deps, data_deps) in adjacency_list.items():
        all_lines.update(ctrl_deps)
        all_lines.update(data_deps)

    for ln in all_lines:
        cgraph[ln] = set()

    for ln in adjacency_list:

        cgraph[ln].update(adjacency_list[ln][0])
        cgraph[ln].update(adjacency_list[ln][1])
    return cgraph


def invert_graph(adjacency_list_combined):
    igraph = {}
    all_nodes = set(adjacency_list_combined.keys())
    for ln_key, dependents in adjacency_list_combined.items():
        all_nodes.update(dependents)

    for node in all_nodes:
        igraph[node] = set()

    for ln_source, dependents in adjacency_list_combined.items():
        for ln_target in dependents:

            igraph[ln_target].add(ln_source)
    return igraph


def create_backward_slice(combined_graph: dict, slice_lines: set[int]):
    if not slice_lines:
        return []


    graph_nodes = set(combined_graph.keys())
    for nodes_in_val in combined_graph.values():
        graph_nodes.update(nodes_in_val)

    if not any(sl in graph_nodes for sl in slice_lines):

        return sorted(list(slice_lines))

    inverted_adjacency_list = invert_graph(combined_graph)

    return create_forward_slice(inverted_adjacency_list, slice_lines)


def perform_slice(
    code_file_path_for_reading: str,
    nodes_csv_path: str,
    edges_csv_path: str,
    slice_lines: set[int],
    slice_type: str,
    data_flow_only: bool,
    verbose_output: bool,
    original_code_filename: str,
    return_graph: bool = False,
    graph_detail_level: str = 'slice',
    program_graph_edge_types: str = 'ddg'
) -> tuple[set[int], dict, dict, nx.DiGraph | None]:


    graph_to_return: nx.DiGraph | None = None
    full_program_graph: nx.DiGraph | None = None


    if not os.path.exists(nodes_csv_path):
        print(f"Error: nodes.csv not found at {nodes_csv_path}. Joern parsing might have failed or path is incorrect.")
        return set(), {}, {}, None
    if not os.path.exists(edges_csv_path):
        print(f"Error: edges.csv not found at {edges_csv_path}. Joern parsing might have failed or path is incorrect.")
        return set(), {}, {}, None
    if not os.path.exists(code_file_path_for_reading):
        print(f"Error: Code file not found at {code_file_path_for_reading} for reading.")
        return set(), {}, {}, None

    try:
        nodes_df_raw = pd.read_csv(nodes_csv_path, sep='\t')
        edges_df_raw = pd.read_csv(edges_csv_path, sep='\t')
    except Exception as e:
        print(f"Error reading CSV files: {e}")
        return set(), {}, {}, None
    code_map = read_code_file(code_file_path_for_reading)


    try:
        with open(code_file_path_for_reading, 'r', encoding='utf-8') as f_raw_code:
            raw_code_lines_list = [line.rstrip('\n') for line in f_raw_code.readlines()]
    except Exception as e:
        print(f"Error reading raw code file {code_file_path_for_reading}: {e}")
        return set(), {}, {}, None


    if edges_df_raw.empty:
        edges_df_renamed = pd.DataFrame(columns=['innode', 'outnode', 'etype', 'dataflow'])
    else:

        edge_column_map = {
            'start': 'innode',
            'end': 'outnode',
            'type': 'etype',
            'var': 'dataflow'
        }
        edges_df_renamed = edges_df_raw.rename(columns=edge_column_map)


        for col_ensure in ['innode', 'outnode', 'etype']:
            if col_ensure not in edges_df_renamed.columns:
                edges_df_renamed[col_ensure] = pd.NA
                if verbose_output:
                    print(f"Warning: Essential edge column '{col_ensure}' (expected from CSV mapping) not found after rename. Defaulting to NA.")

        if 'dataflow' not in edges_df_renamed.columns:
            edges_df_renamed['dataflow'] = ""
            if verbose_output:
                print(f"Warning: 'dataflow' column (expected from CSV 'var') not found. Defaulting to empty string.")

    if not edges_df_renamed.empty and 'etype' in edges_df_renamed.columns and 'dataflow' in edges_df_renamed.columns:
        is_reaching_def = edges_df_renamed['etype'] == 'REACHING_DEF'
        has_invalid_dataflow = edges_df_renamed['dataflow'].isna() | (edges_df_renamed['dataflow'] == '')| (edges_df_renamed['dataflow'] is None)
        condition_to_drop = is_reaching_def & has_invalid_dataflow
        num_dropped = condition_to_drop.sum()
        if verbose_output and num_dropped > 0:
            print(f"Filtered out {num_dropped} 'REACHING_DEF' edges with null or empty 'dataflow' property.")
        edges_df_renamed = edges_df_renamed[~condition_to_drop].copy()

    nodes_df_extracted, node_indices, node_ids, line_numbers_from_nodes, node_id_to_ln_map = \
        extract_nodes_with_location_info(nodes_df_raw, edges_df_renamed, raw_code_lines_list)

    if return_graph:

        if not nodes_df_extracted.empty and not edges_df_renamed.empty:
            if verbose_output:
                print(f"Building full program graph with edge types: {program_graph_edge_types}")
            full_program_graph = build_full_graph_nx(
                nodes_df_extracted,
                edges_df_renamed,
                program_graph_edge_types
            )
            if graph_detail_level == 'program':
                graph_to_return = full_program_graph
            if verbose_output and full_program_graph is not None:
                print(f"Full program graph built with {full_program_graph.number_of_nodes()} nodes and {full_program_graph.number_of_edges()} edges.")
            elif verbose_output and full_program_graph is None:
                 print("Full program graph construction resulted in None or an empty graph.")
        elif verbose_output:
            print("Warning: Cannot build graph as nodes_df_extracted or edges_df_renamed is empty.")

    function_name_to_definition_map = {}
    if not nodes_df_extracted.empty and 'id' in nodes_df_extracted.columns and not edges_df_renamed.empty:
        function_nodes = nodes_df_extracted[nodes_df_extracted['_label'] == 'Function']
        if verbose_output: print(f"DEBUG FormalParamExtraction: Found {len(function_nodes)} 'Function' nodes.")
        for _, func_node in function_nodes.iterrows():
            func_name = func_node.get('code')
            func_id_str = str(func_node.get('id'))
            func_line = node_id_to_ln_map.get(func_id_str)
            if verbose_output: print(f"\n  DEBUG FormalParamExtraction: Processing Function node: ID={func_id_str}, Name='{func_name}', Line={func_line}")
            if func_name and func_id_str:
                formal_params_info = []
                try:
                    current_func_id_int = int(func_id_str)
                    function_def_edge = edges_df_renamed[
                        (edges_df_renamed['innode'] == current_func_id_int) &
                        (edges_df_renamed['etype'] == 'IS_FUNCTION_OF_AST')
                    ]
                except ValueError: function_def_edge = pd.DataFrame()
                except KeyError as e:
                    if verbose_output: print(f"    DEBUG FormalParamExtraction: KeyError when accessing columns for IS_FUNCTION_OF_AST edge: {e}")
                    function_def_edge = pd.DataFrame()
                if verbose_output: print(f"    DEBUG FormalParamExtraction: Found {len(function_def_edge)} 'IS_FUNCTION_OF_AST' edges from Function {func_id_str}.")
                if not function_def_edge.empty:
                    func_def_node_id_int = function_def_edge.iloc[0]['outnode']
                    func_def_node_id_str = str(func_def_node_id_int)
                    func_def_node_details_rows = nodes_df_extracted[nodes_df_extracted['id'] == func_def_node_id_str]
                    is_correct_func_def = False
                    func_def_node_label = "N/A"
                    if not func_def_node_details_rows.empty:
                        func_def_node_label = func_def_node_details_rows.iloc[0].get('_label')
                        if func_def_node_label == 'FunctionDef': is_correct_func_def = True
                    if verbose_output: print(f"      DEBUG FormalParamExtraction: Potential FunctionDef ID={func_def_node_id_str}, Label='{func_def_node_label}'.")
                    if is_correct_func_def:
                        if verbose_output: print(f"      DEBUG FormalParamExtraction: Confirmed FunctionDef ID={func_def_node_id_str}.")
                        param_list_children = get_ast_children_sorted(func_def_node_id_str, 'ParameterList', nodes_df_extracted, edges_df_renamed, node_id_to_ln_map, sort_key='childNum')
                        if verbose_output: print(f"      DEBUG FormalParamExtraction: Found {len(param_list_children)} ParameterList children for FunctionDef {func_def_node_id_str}.")
                        if param_list_children:
                            param_list_node_id_str = param_list_children[0]['id']
                            if verbose_output: print(f"        DEBUG FormalParamExtraction: Using ParameterList ID={param_list_node_id_str} (Code: '{param_list_children[0].get('code')}').")
                            parameter_nodes = get_ast_children_sorted(param_list_node_id_str, 'Parameter', nodes_df_extracted, edges_df_renamed, node_id_to_ln_map, sort_key='childNum')
                            if verbose_output: print(f"        DEBUG FormalParamExtraction: Found {len(parameter_nodes)} Parameter children for ParameterList {param_list_node_id_str}.")
                            for param_idx, param_node_info in enumerate(parameter_nodes):
                                if verbose_output: print(f"          DEBUG FormalParamExtraction: Processing Parameter child {param_idx}: ID={param_node_info['id']}, Code='{param_node_info.get('code')}', childNum={param_node_info.get('childNum')}")
                                param_name_nodes = get_ast_children_sorted(param_node_info['id'], 'Identifier', nodes_df_extracted, edges_df_renamed, node_id_to_ln_map, sort_key='childNum')
                                param_name = param_name_nodes[0]['code'] if param_name_nodes else param_node_info.get('code')
                                if verbose_output: print(f"            DEBUG FormalParamExtraction: Param Name Nodes found: {len(param_name_nodes)}. Deduced Name: '{param_name}'")
                                param_type_nodes = get_ast_children_sorted(param_node_info['id'], 'ParameterType', nodes_df_extracted, edges_df_renamed, node_id_to_ln_map, sort_key='childNum')
                                param_type_name = param_type_nodes[0]['code'] if param_type_nodes else "unknown_type"
                                if verbose_output: print(f"            DEBUG FormalParamExtraction: Param Type Nodes found: {len(param_type_nodes)}. Deduced Type: '{param_type_name}'")
                                formal_params_info.append({
                                    'id': param_node_info['id'], 'name': param_name, 'type': param_type_name,
                                    'line': param_node_info['line'], 'childNum': param_node_info['childNum']
                                })
                        elif verbose_output: print(f"      DEBUG FormalParamExtraction: No ParameterList found for FunctionDef {func_def_node_id_str}.")
                    elif verbose_output: print(f"    DEBUG FormalParamExtraction: No suitable FunctionDef child found for Function {func_id_str} via 'IS_FUNCTION_OF_AST' or child not '_label=FunctionDef'.")
                else:
                    if verbose_output: print(f"    DEBUG FormalParamExtraction: No 'IS_FUNCTION_OF_AST' edge found from Function {func_id_str} to a FunctionDef.")
                if func_line is not None:
                    function_name_to_definition_map[func_name] = {
                        'id': func_id_str, 'entry_line': func_line, 'formal_params': formal_params_info
                    }
                    if verbose_output: print(f"    DEBUG FormalParamExtraction: ADDED to map: '{func_name}' -> id:{func_id_str}, entry_line:{func_line}, params:{len(formal_params_info)}")
                elif verbose_output: print(f"    DEBUG FormalParamExtraction: NOT ADDED to map (missing entry_line for func_id {func_id_str}): '{func_name}'")
            elif verbose_output: print(f"  DEBUG FormalParamExtraction: Skipping Function node ID={func_id_str} due to missing name or ID.")

    if verbose_output:
        print(f"Function definition map created with {len(function_name_to_definition_map)} entries.")
        for fname, finfo in function_name_to_definition_map.items():
            print(f"  DEBUG Func Map: Func: {fname}, ID: {finfo['id']}, EntryLine: {finfo['entry_line']}, Params: {len(finfo['formal_params'])}")
            for p_idx, p_info in enumerate(finfo['formal_params']):
                print(f"    DEBUG Func Map: Param {p_idx}: Name: {p_info['name']}, Type: {p_info['type']}, ID: {p_info['id']}, Line: {p_info['line']}, childNum: {p_info['childNum']}")

    if not line_numbers_from_nodes:
        print(f"Warning: Joern output for {original_code_filename} yielded no nodes with location information.")

        if not any(sl in node_id_to_ln_map.values() for sl in slice_lines):
             print(f"Error: Slice lines {slice_lines} do not correspond to any parsed node with location info in {original_code_filename}.")
             return set(), {}, {}, None


    if not all(sl in code_map for sl in slice_lines):
        max_line = max(code_map.keys()) if code_map else 0
        missing_lines = [sl for sl in slice_lines if sl not in code_map]
        print(f"Error: One or more slice line numbers in {missing_lines} (from target {slice_lines}) are not present in the code file {original_code_filename} (max line: {max_line}).")
        return set(), {}, {}, None

    adjacency_list_detailed = create_adjacency_list(
        line_numbers_from_nodes, node_id_to_ln_map, nodes_df_extracted, edges_df_renamed,
        function_name_to_definition_map, data_flow_only, verbose_output=verbose_output
    )
    if verbose_output:
        print(f"Detailed line-level adjacency_list created for slicing (slice_lines: {slice_lines}).")

    combined_line_graph = combine_control_and_data_adjacents(adjacency_list_detailed)
    if verbose_output:
        print(f"Combined line_graph created for slicing.")

    forward_sliced_lines = set()
    backward_sliced_lines = set()


    if slice_type == "forward" or slice_type == "combined":
        forward_calculated = create_forward_slice(combined_line_graph, slice_lines)
        forward_sliced_lines = set(forward_calculated if isinstance(forward_calculated, list) else [])
        if verbose_output:
            print(f"Forward sliced lines (line-level based, count: {len(forward_sliced_lines)}): {sorted(list(forward_sliced_lines))}")


    if slice_type == "backward" or slice_type == "combined":
        backward_calculated = create_backward_slice(combined_line_graph, slice_lines)
        backward_sliced_lines = set(backward_calculated if isinstance(backward_calculated, list) else [])
        if verbose_output:
            print(f"Backward sliced lines (line-level based, count: {len(backward_sliced_lines)}): {sorted(list(backward_sliced_lines))}")

    final_sliced_lines = set()
    if slice_type == "forward":
        final_sliced_lines = forward_sliced_lines
    elif slice_type == "backward":
        final_sliced_lines = backward_sliced_lines
    elif slice_type == "combined":
        final_sliced_lines = forward_sliced_lines.union(backward_sliced_lines)
    else:
        if verbose_output:
            print(f"Warning: Unknown slice_type '{slice_type}'. Defaulting to empty slice.")

    if verbose_output:
        print(f"Final selected slice type: '{slice_type}', resulting lines (count: {len(final_sliced_lines)}): {sorted(list(final_sliced_lines))}")


    if return_graph and graph_detail_level == 'slice':
        if full_program_graph is not None:
            if final_sliced_lines and node_id_to_ln_map:


                sliced_node_ids = {
                    node_id_str for node_id_str, ln in node_id_to_ln_map.items() if ln in final_sliced_lines
                }
                if sliced_node_ids:
                    if verbose_output:
                        print(f"Extracting slice subgraph for {len(sliced_node_ids)} node IDs corresponding to {len(final_sliced_lines)} sliced lines.")
                    graph_to_return = extract_slice_subgraph_nx(full_program_graph, sliced_node_ids)
                    if verbose_output and graph_to_return is not None:
                        print(f"Slice subgraph extracted with {graph_to_return.number_of_nodes()} nodes and {graph_to_return.number_of_edges()} edges.")
                    elif verbose_output and graph_to_return is None:
                        print("Slice subgraph extraction resulted in None or an empty graph.")
                elif verbose_output:
                    print("Warning: No Joern node IDs correspond to the final_sliced_lines for subgraph extraction. Slice graph will be empty.")
                    graph_to_return = nx.DiGraph()
            elif verbose_output:
                print("Warning: Cannot extract slice subgraph because final_sliced_lines or node_id_to_ln_map is empty/None. Slice graph will be empty.")
                graph_to_return = nx.DiGraph()
        elif verbose_output:
            print("Warning: Cannot extract slice subgraph because full_program_graph was not built (is None). Slice graph will be None.")


    return final_sliced_lines, adjacency_list_detailed, code_map, graph_to_return


def run_slicer(args):
    input_dir_arg = args.input_dir
    original_filename = args.filename
    target_line_no = args.line
    output_dir_for_slices = args.output_dir
    data_flow_only = args.data_flow_only
    verbose_mode = args.verbose

    original_source_file_path = Path(input_dir_arg) / original_filename
    if not original_source_file_path.is_file():
        print(f"Error: Input C file not found at {original_source_file_path}")
        sys.exit(1)

    input_dir_for_joern = str(original_source_file_path.parent)

    joern_parse_executable = "slicer/joern/joern-parse"


    with tempfile.TemporaryDirectory() as joern_cwd_temp_dir:
        joern_cwd_path = Path(joern_cwd_temp_dir)
        joern_command = [joern_parse_executable, input_dir_for_joern]

        if verbose_mode:
            print(f"Executing Joern command: {' '.join(joern_command)} in CWD: {joern_cwd_path}")


        try:
            process = subprocess.run(joern_command, check=True, capture_output=True, text=True, cwd=str(joern_cwd_path))
            if verbose_mode and process.stdout:
                print("Joern stdout:\n", process.stdout)
            if process.stderr and (verbose_mode or "error" in process.stderr.lower() or "exception" in process.stderr.lower()):
                print("Joern stderr:\n", process.stderr, file=sys.stderr)
        except subprocess.CalledProcessError as e:
            print(f"Error during Joern execution (joern-parse, return code {e.returncode}): {e}")
            if e.stdout: print(f"Joern stdout (error):\n{e.stdout}")
            if e.stderr: print(f"Joern stderr (error):\n{e.stderr}")
            sys.exit(1)
        except FileNotFoundError:
            print(f"Error: Joern executable not found at '{joern_parse_executable}'. Please check the path.")
            sys.exit(1)


        input_dir_basename = Path(input_dir_for_joern).name
        nodes_csv_path = joern_cwd_path / "parsed" / input_dir_basename / original_filename / "nodes.csv"
        edges_csv_path = joern_cwd_path / "parsed" / input_dir_basename / original_filename / "edges.csv"

        if verbose_mode:
            print(f"Expected nodes.csv path: {nodes_csv_path}")
            print(f"Expected edges.csv path: {edges_csv_path}")

        if not nodes_csv_path.exists() or not edges_csv_path.exists():
            print(f"Error: Joern CSV output not found after parsing. Searched for:\nNodes: {nodes_csv_path}\nEdges: {edges_csv_path}")
            if verbose_mode:
                parsed_output_location = joern_cwd_path / "parsed"
                if parsed_output_location.exists():
                    print(f"Contents of {parsed_output_location} for debugging:")
                    for item in parsed_output_location.rglob('*'):
                        print(f"  {item}")
            sys.exit(1)


        target_lines_set = {target_line_no}


        forward_sliced_lines, adj_list_fwd, code_map_fwd, _ = perform_slice(
            code_file_path_for_reading=str(original_source_file_path),
            nodes_csv_path=str(nodes_csv_path),
            edges_csv_path=str(edges_csv_path),
            slice_lines=target_lines_set,
            slice_type="forward",
            data_flow_only=data_flow_only,
            verbose_output=verbose_mode,
            original_code_filename=original_filename,
            return_graph=False
        )


        backward_sliced_lines, adj_list_bwd, code_map_bwd, graph_for_cli_viz = perform_slice(
            code_file_path_for_reading=str(original_source_file_path),
            nodes_csv_path=str(nodes_csv_path),
            edges_csv_path=str(edges_csv_path),
            slice_lines=target_lines_set,
            slice_type="backward",
            data_flow_only=data_flow_only,
            verbose_output=verbose_mode,
            original_code_filename=original_filename,
            return_graph=verbose_mode,
            graph_detail_level='program',
            program_graph_edge_types='cfg+ddg'
        )

        os.makedirs(output_dir_for_slices, exist_ok=True)


        forward_output_path = Path(output_dir_for_slices) / (original_filename + '.forward')
        with open(forward_output_path, 'w', encoding='utf-8') as fp:

            with open(original_source_file_path, 'r', encoding='utf-8') as src_fp:
                all_source_lines = src_fp.readlines()
            for i, line_content in enumerate(all_source_lines):
                if (i + 1) in forward_sliced_lines:
                    fp.write(line_content)
        if verbose_mode: print(f"Forward slice written to: {forward_output_path}")


        backward_output_path = Path(output_dir_for_slices) / (original_filename + '.backward')
        with open(backward_output_path, 'w', encoding='utf-8') as fp:

            with open(original_source_file_path, 'r', encoding='utf-8') as src_fp:
                 all_source_lines_bwd = src_fp.readlines()
            for i, line_content in enumerate(all_source_lines_bwd):
                if (i + 1) in backward_sliced_lines:
                    fp.write(line_content)
        if verbose_mode: print(f"Backward slice written to: {backward_output_path}")

        if verbose_mode:
            print(f'\n--- Verbose Output for {original_filename} (Slice on line {target_line_no}) ---')


            if adj_list_bwd and code_map_bwd:
                 visual_graph_output_path_prefix = Path(output_dir_for_slices) / (original_filename + f"_slice_{target_line_no}_pdg_visualization")
                 create_visual_graph(code_map_bwd, adj_list_bwd, str(visual_graph_output_path_prefix), verbose_render=True)

            if graph_for_cli_viz and verbose_mode:
                print(f"  NetworkX graph for CLI visualization (if enabled) has {graph_for_cli_viz.number_of_nodes()} nodes and {graph_for_cli_viz.number_of_edges()} edges.")


            combined_slice_for_cli = sorted(list(forward_sliced_lines.union(backward_sliced_lines)))
            print('============== Combined Slice (Forward U Backward) =================')
            with open(original_source_file_path, 'r', encoding='utf-8') as src_fp_combined:
                all_source_lines_combined = src_fp_combined.readlines()
            for i, line_content in enumerate(all_source_lines_combined):
                if (i + 1) in combined_slice_for_cli:
                    print(f"{i+1}\t-> {line_content.rstrip()}")
            print('===============================================')


    if verbose_mode:
        print(f"Slicing process for '{original_filename}' on line {target_line_no} completed. Output in '{output_dir_for_slices}'.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="C Code Slicer using Joern. Integrates file parsing and slicing.")
    parser.add_argument('--input_dir', required=True, help='Directory of the C source file.')
    parser.add_argument('--filename', required=True, help='Name of the C source file (e.g., test1.c).')
    parser.add_argument('--line', required=True, type=int, help='Line number in the C file for slice criteria.')
    parser.add_argument('--output_dir', required=True, help='Directory where slice results (.forward, .backward files) will be stored.')
    parser.add_argument('--data_flow_only', action='store_true', help='If set, slicing will only consider data flow dependencies.')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output for the script, including Joern execution details.')

    parsed_args = parser.parse_args()
    run_slicer(parsed_args)

def slice_code_from_string(
    source_code: str,
    target_lines: list[int],
    slice_type: str = "backward",
    data_flow_only: bool = False,
    verbose: bool = False,
    visualization_output_dir: str = None,
    return_graph: bool = False,
    graph_detail_level: str = 'slice',
    program_graph_edge_types: str = 'cfg+ddg'
) -> tuple[str, nx.DiGraph | None]:
    if not target_lines:
        if verbose:
            print("Warning: No target lines provided for slicing. Returning empty slice.")
        return "", None


    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir_path = Path(temp_dir_name)


        original_filename = "temp_source.c"
        temp_source_file_path = temp_dir_path / original_filename


        source_lines_list = source_code.splitlines(keepends=True)
        with open(temp_source_file_path, 'w', encoding='utf-8') as f:
            f.writelines(source_lines_list)

        if verbose:
            print(f"Temporary source file created at: {temp_source_file_path}")

        joern_parse_executable = "slicer/joern/joern-parse"


        joern_process_cwd = temp_dir_path
        joern_command_final = [joern_parse_executable, "."]

        if verbose:
            print(f"Executing Joern command: {' '.join(joern_command_final)} in CWD: {joern_process_cwd}")

        parsed_dir_in_temp = joern_process_cwd / "parsed"
        if parsed_dir_in_temp.exists() and parsed_dir_in_temp.is_dir():
            if verbose: print(f"Removing existing '{parsed_dir_in_temp}' directory before Joern run.")
            shutil.rmtree(parsed_dir_in_temp)

        try:
            process = subprocess.run(joern_command_final, check=True, capture_output=True, text=True, cwd=str(joern_process_cwd))


        except subprocess.CalledProcessError as e:
            print(f"Error during Joern execution (joern-parse, return code {e.returncode}): {e}")
            if e.stdout: print(f"Joern stdout (error):\n{e.stdout}")
            if e.stderr: print(f"Joern stderr (error):\n{e.stderr}")
            return "", None
        except FileNotFoundError:
            print(f"Error: Joern executable not found at '{joern_parse_executable}'. Please check the path.")
            return "", None


        nodes_csv_path = joern_process_cwd / "parsed" / original_filename / "nodes.csv"
        edges_csv_path = joern_process_cwd / "parsed" / original_filename / "edges.csv"

        if verbose:
            print(f"Expected nodes.csv path: {nodes_csv_path}")
            print(f"Expected edges.csv path: {edges_csv_path}")

        if not nodes_csv_path.exists() or not edges_csv_path.exists():
            print(f"Error: Joern CSV output not found. Searched for:\nNodes: {nodes_csv_path}\nEdges: {edges_csv_path}")
            if verbose and parsed_dir_in_temp.exists():
                print(f"Contents of {parsed_dir_in_temp}:")
                for item in parsed_dir_in_temp.rglob('*'):
                    print(f"  {item}")
            return "", None

        final_sliced_line_numbers, adj_list_for_viz, code_map_for_viz, returned_graph = perform_slice(
            code_file_path_for_reading=str(temp_source_file_path),
            nodes_csv_path=str(nodes_csv_path),
            edges_csv_path=str(edges_csv_path),
            slice_lines=set(target_lines),
            slice_type=slice_type,
            data_flow_only=data_flow_only,
            verbose_output=verbose,
            original_code_filename=original_filename,
            return_graph=return_graph,
            graph_detail_level=graph_detail_level,
            program_graph_edge_types=program_graph_edge_types
        )

        if not final_sliced_line_numbers:
            if verbose:
                print("Slicing resulted in no lines.")
            return "", returned_graph

        if verbose and visualization_output_dir and adj_list_for_viz and code_map_for_viz:
            try:
                Path(visualization_output_dir).mkdir(parents=True, exist_ok=True)
                viz_filename_prefix = f"{Path(original_filename).stem}_slice_on_{'_'.join(map(str, sorted(list(target_lines))))}_{slice_type}"
                viz_full_prefix = Path(visualization_output_dir) / viz_filename_prefix
                if verbose: print(f"Attempting to render visualization to prefix: {viz_full_prefix}")
                create_visual_graph(code_map_for_viz, adj_list_for_viz, str(viz_full_prefix), verbose_render=True)
            except Exception as e_viz:
                print(f"Warning: Failed to create visualization: {e_viz}")

        output_code_lines = []

        for i, line_content in enumerate(source_lines_list):
            current_line_num_1_based = i + 1
            if current_line_num_1_based in final_sliced_line_numbers:
                output_code_lines.append(line_content)

        return "".join(output_code_lines), returned_graph
