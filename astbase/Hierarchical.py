from collections import deque
import json
import logging
import math
import random
import pickle
import os
import re
import signal
import time
from concurrent.futures import ProcessPoolExecutor
import traceback
from openai import OpenAI
from tqdm import tqdm
from xinference.client import Client
import Pattern
import numpy as np


def clustering(working_set):
    import random
    working_sets = {}
    random.seed(1000)
    random.shuffle(working_set)
    for pattern in working_set:
        if not pattern.getBeforePattern().getRootNode().type.type_name in working_sets:
            working_sets[pattern.getBeforePattern().getRootNode().type.type_name] = []

        working_sets[pattern.getBeforePattern().getRootNode().type.type_name].append(pattern)

    for filename in os.listdir('./pkls/'):
        file_path = os.path.join('./pkls/', filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                os.rmdir(file_path)
        except Exception as e:
            print(f"error deleting files in {file_path}: {e}")

    for root_type in working_sets:
        if root_type == "unit" or root_type == "block"  or root_type == 'translation_unit':
            continue
        working_set = working_sets[root_type]
        working_set.sort(key=HierarchicalCluster.sizeofPattern, reverse=False)

        f = open('./pkls/' + root_type + '.pkl', 'wb+')
        pickle.dump(working_set, f)
        f.close()


def run_cluster(llm=False, resume=False):
    if not resume:
        print('no resume')
        for filename in os.listdir('./clusters/'):
            file_path = os.path.join('./clusters/', filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.remove(file_path)
                elif os.path.isdir(file_path):
                    os.rmdir(file_path)
            except Exception as e:
                print(f"error deleting files in {file_path}: {e}")
    else:
        pass
    working_sets = [os.path.splitext(filename)[0] for filename in os.listdir('./pkls/')]
    finished_working_sets = [os.path.splitext(filename)[0].replace('_cluster', '') for filename in os.listdir('./clusters/')]
    with ProcessPoolExecutor(max_workers=os.cpu_count()-1) as executor:
        if not resume:
            print('no resume')
            futures = [
                executor.submit(clusterSubset, root_type, llm, i)
                for i, root_type in enumerate(working_sets)
                if root_type not in {"unit", "block", "translation_unit"}
            ]
        else:
            futures = [
                executor.submit(clusterSubset, root_type, llm, i)
                for i, root_type in enumerate(working_sets)
                if root_type not in finished_working_sets and root_type not in {"unit", "block", "translation_unit"}
            ]
        for future in futures:
            try:
                future.result()
            except Exception as e:
                traceback.print_exc()
    '''for root_type in self.working_sets:
        if root_type == "unit" or root_type == "block" or root_type == 'translation_unit' or root_type=='block_content':
            continue
        self.clusterSubset(root_type, llm)'''


def clusterSubset(root_type, llm, i):
    f = open('./pkls/' + root_type + '.pkl', 'rb')
    working_set = pickle.load(f)
    f.close()

    iii = 0
    cluster_node_set = []

    while iii < len(working_set):
        jjj = iii + 1
        while jjj < len(working_set):
            if working_set[iii] == working_set[jjj]:
                del working_set[jjj]
            else:
                jjj += 1
        iii += 1
    stack = []
    total = len(working_set)
    with tqdm(total=total, desc=f"Processing {root_type}", unit="node") as pbar:
        while len(working_set) > 1:
            prelen = len(working_set)
            flag = False
            if len(stack) == 0:
                iii = random.randint(0, len(working_set)-1)
                stack.append(working_set[iii])
            pattern1 = stack[-1]
            gen_set = []
            before = time.time()
            bound_exist = False
            for i in range(len(working_set)):
                pattern2 = working_set[i]
                if pattern1 == pattern2 or i == iii or (pattern1.index == pattern2.index):
                    continue
                pattern3 = pattern1.mergeEditPattern(pattern2)
                if pattern3.hasUnboundHoles() or pattern3.isAmbiguous():
                    continue
                else:
                    bound_exist = True
                    gen_set.append([pattern1, pattern2, pattern3])
            if len(gen_set) == 0:
                flag = True
                gen_set.append([pattern1, None, None])
            if not bound_exist:
                flag = True
                gen_set = [[pattern1, None, None]]
            if not flag:
                gen_set.sort(key=HierarchicalCluster.numOfUnmodifiedMappings, reverse=True)
                gen_set.sort(key=HierarchicalCluster.numOfUnmodifiedMappingsWithLabels, reverse=True)
                gen_set.sort(key=HierarchicalCluster.sizeOfGeneralizedTrees, reverse=False)
                gen_set.sort(key=HierarchicalCluster.numOfHoles, reverse=False)
                gen_set.sort(key=HierarchicalCluster.numOfModifiedMappings, reverse=True)
                if gen_set[0][0].getAfterPattern().getRootNode() == None:
                    gen_set.sort(key=HierarchicalCluster.sizeofBeforePattern, reverse=True)
                gen_set.sort(key=HierarchicalCluster.hasUnboundHoles, reverse=False)
                gen_set = gen_set[:3]
            if not flag:
                for g in gen_set:
                    try:
                        merged_before_cond, merged_after_cond = g[0].merge_func(g[1], llm)
                        if merged_before_cond is not None:
                            condition = merged_before_cond
                        else:
                            condition = 'None'
                        if "None" in condition or "None" in merged_after_cond:
                            g[2].before_condition, g[2].after_condition = "None", "None"
                        else:
                            g[2].before_condition, g[2].after_condition = merged_before_cond, merged_after_cond
                    except:
                        g[2].before_condition, g[2].after_condition = "None", "None"
                        traceback.print_exc()
                if llm:
                    gen_set.sort(key=HierarchicalCluster.hasIntersection, reverse=True)
            if flag or ("None" in gen_set[0][2].before_condition and llm):
                e1_pattern = gen_set[0][0]
                try:
                    stack.remove(gen_set[0][0])
                except:
                    pass
                e3_node = HierarchicalNode()
                e3_node.pattern = e1_pattern
                e3_node.children.append(None)
                e3_node.children.append(None)
                cluster_node_set.append(e3_node)
                try:
                    working_set.remove(e1_pattern)
                except:
                    logging.error('e1 error')
            else:
                if gen_set[0][1] in stack:
                    e1_pattern = gen_set[0][0]
                    try:
                        stack.remove(gen_set[0][0])
                    except:
                        pass
                    e2_pattern = gen_set[0][1]
                    try:
                        stack.remove(gen_set[0][1])
                    except:
                        pass
                    new_pattern = gen_set[0][2]
                    e1_node = None
                    e2_node = None

                    for hierarchical_node in cluster_node_set:
                        if hierarchical_node.pattern == e1_pattern:
                            e1_node = hierarchical_node
                            break
                    for hierarchical_node in cluster_node_set:
                        if hierarchical_node.pattern == e2_pattern:
                            e2_node = hierarchical_node
                            break
                    if e1_node is None:
                        e1_node = HierarchicalNode()
                        e1_node.pattern = e1_pattern
                        cluster_node_set.append(e1_node)
                    if e2_node is None:
                        e2_node = HierarchicalNode()
                        e2_node.pattern = e2_pattern
                        cluster_node_set.append(e2_node)

                    e3_node = HierarchicalNode()
                    e3_node.pattern = new_pattern
                    e3_node.children.append(e1_node)
                    e3_node.children.append(e2_node)
                    e1_node.parent = e3_node
                    e2_node.parent = e3_node
                    cluster_node_set.append(e3_node)
                    if not flag:
                        working_set.append(new_pattern)
                    try:
                        working_set.remove(e1_pattern)
                    except:
                        logging.error('e1 error')
                    try:
                        working_set.remove(e2_pattern)
                    except:
                        logging.info('e2 error')
                else:
                    stack.append(gen_set[0][1])
            curlen = len(working_set)
            pbar.update(prelen-curlen)

    f = open('./clusters/' + root_type + "_cluster.pkl", 'wb')
    pickle.dump(cluster_node_set, f)
    f.close()


def getSemanticMatchString(pattern, train_subtree, test_subtree):
    hole_dict_train = {}
    hole_dict_test = {}
    pattern.matchAst(train_subtree, hole_dict_train)
    pattern.matchAst(test_subtree, hole_dict_test)
    string_list = []
    for hole in hole_dict_train:
        train_subtree_hole_string = ""
        train_hole_subtrees = hole_dict_train[hole]
        for hole_subtree in train_hole_subtrees:
            train_subtree_hole_string = train_subtree_hole_string + hole_subtree.getCode()
        test_subtree_hole_string = ""
        test_hole_subtrees = hole_dict_test[hole]
        for hole_subtree in test_hole_subtrees:
            test_subtree_hole_string = test_subtree_hole_string + hole_subtree.getCode()
        string_list.append(
            [train_subtree_hole_string, test_subtree_hole_string])
    return string_list


def timeout_handler(signum, frame):
    raise TimeoutError("Timeout")


def applyGroup(pattern_src_trees):
    patterns = []
    new_asts = []
    subtree_root_ids = []
    for pattern_src_tree in pattern_src_trees:
        pattern = pattern_src_tree[0][0]
        src_tree = pattern_src_tree[1]
        try:
            patterns.append(pattern)
            new_asts.append(pattern.applyPattern(src_tree))
            subtree_root_ids.append(pattern.matchAst(src_tree))

        except:
            pass
    return patterns, new_asts, subtree_root_ids


class HierarchicalNode:
    def __init__(self):
        self.parent = None
        self.children = []
        self.pattern = None


    def __str__(self):

        return self.pattern.getCode()

    def __eq__(self, other):
        return self.pattern == other.pattern


class HierarchicalCluster:
    def __init__(self, working_set, llm=False):
        self.working_set = working_set
        self.working_sets = {}
        self.hierarchical_nodes = []
        self.patterns_ = []
        self.llm = llm


    @staticmethod
    def sizeofPattern(pattern):
        return len(pattern)

    @staticmethod
    def hasIntersection(pattern):
        if "None" in pattern[2].before_condition_formula or 'None' in pattern[2].before_condition_formula:
            return 0
        else:
            return 1

    @staticmethod
    def sizeofBeforePattern(pattern):
        return len(pattern[2])

    @staticmethod
    def hasUnboundHoles(pattern):
        if pattern[2].hasUnboundHoles() or pattern[2].isAmbiguous():
            return 1
        else:
            return 0

    @staticmethod
    def numOfModifiedMappings(pattern):
        num = 0
        for node_id in pattern[2].getNodeMap():
            if node_id in pattern[2].getModifiedTrees():
                num += 1
        return num

    @staticmethod
    def numOfHoles(pattern):
        return len(pattern[2].getBeforeHolesSet().union(pattern[2].getAfterHolesSet()))

    @staticmethod
    def sizeOfGeneralizedTrees(pattern):
        return (len(pattern[0]) + len(pattern[1])) / 2 - len(pattern[2])

    @staticmethod
    def numOfUnmodifiedMappingsWithLabels(pattern):
        num = 0
        for node_id in pattern[1].getNodeMap():
            if not node_id in pattern[1].getModifiedTrees() and pattern[1].getBeforePattern().getNodeDict()[
                    node_id].type.type_name != '?':
                num += 1
        return num

    @staticmethod
    def numOfUnmodifiedMappings(pattern):
        num = 0
        for node_id in pattern[1].getNodeMap():
            if not node_id in pattern[1].getModifiedTrees():
                num += 1
        return num

    def _setPattern(self):
        for node in self.hierarchical_nodes:
            pattern = node.pattern if type(node) != Pattern.EditPattern else node

            if pattern.hasUnboundHoles() or pattern.isAmbiguous() or len(pattern.getBeforeHolesSet()) > len(pattern.getBeforePattern()) * 0.5:
                continue


            self.patterns_.append(pattern)
        patterns2 = []
        for i, pattern in enumerate(self.patterns_):
            flag = False
            for j in range(i + 1, len(self.patterns_)):
                if pattern == self.patterns_[j]:
                    flag = True
            if not flag:
                patterns2.append(pattern)
        self.patterns_ = patterns2
        print("pattern number:", len(self.patterns_))

    def get_same_field(self, field1,field2, idx=None):
        client = OpenAI(
            base_url="https://api.deepseek.com",
            api_key=os.getenv("DEEPSEEK_API_KEY", ""),
        )
        replay = 1
        prompt = f"""
Do {field1} and {field2} belong to the same domain?
- You must output in JSON format:
{{
    "is_same":"yes or no(yes for belonging to the same domain, no for not) based on your analysis."
}}
- First, provide a detailed thought process, and then present the output.
"""
        completion = client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {"role": "system", "content": "You are an expert in programming and code analysis."},
            {"role": "user", "content": prompt}
        ],
        temperature=0
        )
        response = completion.choices[0].message.content
        try:
            func_intersection = re.search(r"```json(.*?)```", response, re.DOTALL).group(1)
            func_intersection = json.loads(func_intersection)['is_same']
        except:
            traceback.print_exc()
        if func_intersection == 'yes':
            return True
        else:
            return False

    def get_equivalent_error(self, statement, fullcode, before_condition, idx=None):

        client = OpenAI(
            base_url="https://api.deepseek.com",
            api_key=os.getenv("DEEPSEEK_API_KEY", ""),
        )
        replay = 1
        prompt = f"""

I will provide you with a snippet of C code and a specific statement within it. \
Your task is: To help me analyze whether this statement and its context satisfy the following vulnerable flow trace.
Follow the steps below to determine whether the statement satisfy the following flow trace:
Step 1: Understand the code and the provided statement within it. \
    If the provided statement is too short to understand, answer 'no'.
Step 2: Based on Step 1, determine whether the statement or statements around it contains the corresponding flow entry. \
    Specific identifier names is not needed to be concerned. \
    If the entry is not reflected in the code, answer 'no'.
Step 3: Based on Step 1,2, check rigorously if each propagation element is implemented in the statement and its context. \
    Match Strictly according to the conditions provided by the flow trace. \
    Matching should be performed sequentially in order. \
    Elements that marked with $vulnerable$ are mixed with conditions and anti-conditions, and for anti-conditions, such as 'not validated' or 'not checked,' you should also accurately determine whether these anti-conditions are met. \
    If any of the element is not reflected in the code, answer 'no'. \
    If the order of the elements is not matched, answer 'no'.
Step 4: Determine whether the statement and its context contains the corresponding flow exit, without needing to focus on the specific identifier names except constants. If the exit is not reflected in the code, answer 'no'.
- Infer and determine based on the code, not based on your own understanding and assumption. \
- You must output in JSON format:
{{
    "is_satisfy":"yes or no(yes for code satisfying the flow trace, no for not) based on your analysis."
}}
- First, provide a detailed thought process, and then present the output.


{fullcode}


{statement}


{before_condition}


Output:
"""
        consensus = []
        for _ in range(replay):
            completion = client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": "You are an expert in analysing C language security vulnerabilities."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0
            )
            response = completion.choices[0].message.content
            print(before_condition, flush=True)
            print(response, '\n', idx, flush=True)
            try:
                func_intersection = re.search(r"```json(.*?)```", response, re.DOTALL).group(1)
                func_intersection = json.loads(func_intersection)['is_satisfy']
                consensus.append(func_intersection)
            except:
                traceback.print_exc()
                consensus.append('no')
        if consensus.count('yes') >= math.ceil(replay * 1 / 2):
            return True
        else:
            return False

    def flow_checker(self, vul, fix, before_condition, after_condition):
        client = OpenAI(
            base_url="https://api.deepseek.com",
            api_key=os.getenv("DEEPSEEK_API_KEY", ""),
        )
        replay = 1
        prompt = f"""

I will provide you with a patch written in C code. \
Your task is: Help me determine whether this patch satisfy the transformation from flow trace A into flow trace B in the code.
Follow the steps below to determine whether patch transforms flow trace A into flow trace B in the code:
Step 1: Gain a deep understanding of flow trace A and flow trace B, and analyze the tranformation between them.
Step 2: Based on the transformation of Step 1, identify the statements that potentially need to be modified in the code before applying the patch.
Step 3: Based on Step 2 and patch, determine whether the code after applying the patch contains the potential modification; if there are no modifications or the modification is irrelevant, output 'no'; if there contains the potential modification, output 'yes'.
Step 4: Check whether the modified statements have any grammatical or logical errors, or have mistakenly altered the original high-level functionality of the program. And verify if the identifiers used are appropriate and coherent for the whole code at functional level. If there are any errors, output 'no'; if there are no errors, output 'yes'.
- You must output in JSON format:
{{
    "is_satisfy":"yes or no(yes for code code satisfying the transformation, no for not) based on your analysis."
}}
- First, provide a detailed thought process, and then present the output.


{vul}


{fix}


{before_condition}


{after_condition}


Output:
"""
        consensus = []
        for _ in range(replay):
            completion = client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": "You are an expert in understanding and fixing C language security vulnerabilities. You're good at solving if the program meets the condition."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0
            )
            response = completion.choices[0].message.content

            try:
                func_intersection = re.search(r"```json(.*?)```", response, re.DOTALL).group(1)
                func_intersection = json.loads(func_intersection)['is_satisfy']
                consensus.append(func_intersection)
            except:
                traceback.print_exc()
                consensus.append('no')
        if consensus.count('yes') >= math.ceil(replay * 3 / 5):
            return True
        else:
            return False

    def get_validated_patch(self, fullcode, before_condition):
        client = OpenAI(
            base_url="https://api.deepseek.com",
            api_key=os.getenv("DEEPSEEK_API_KEY", ""),
        )
        replay = 1
        prompt = f"""

I will provide you with a snippet of C code. \
Your task is: To help me analyze whether this code satisfy the following flow trace.
Follow the steps below to determine whether the code satisfy the following flow trace:
Step 1: Determine whether the code contains the corresponding flow entry, without needing to focus on the specific identifier names.
Step 2: Check if each propagation element is implemented in the code, applying lenient matching, without needing to focus on the specific identifier names. If the safety element is not reflected in the code, answer 'no'.
Step 3: Determine whether the code contains the corresponding flow exit, without needing to focus on the specific identifier names.
- You must output in JSON format:
{{
    "is_satisfy":"yes or no(yes for code code satisfying the flow trace, no for not) based on your analysis."
}}
- First, provide a detailed thought process, and then present the output.

{fullcode}


{before_condition}


Output:
"""
        consensus = []
        for _ in range(replay):
            completion = client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": "You are an expert in understanding and fixing C language security vulnerabilities."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0
            )
            response = completion.choices[0].message.content

            try:
                func_intersection = re.search(r"```json(.*?)```", response, re.DOTALL).group(1)
                func_intersection = json.loads(func_intersection)['is_satisfy']
                consensus.append(func_intersection)
            except:
                traceback.print_exc()
                consensus.append('no')
        if consensus.count('yes') >= math.ceil(replay * 3 / 5):
            return True
        else:
            return False

    def applyPattern(self, src_tree, idx, focus=None, fullcode=None):
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(45)
        before_ast = src_tree
        new_asts = []
        new_asts2 = []

        new_ast_group=[]
        new_ast_group2=[]
        pattern_index = []
        for i,pattern in enumerate(self.patterns_):
            try:
                new_asts_temp = pattern.applyPattern(ast=before_ast, focus_statement=focus)

                if len(new_asts_temp) > 0:
                    if len(new_asts_temp[0]) > 0:
                        new_asts.append(new_asts_temp)
                        pattern_index.append(i)
            except TimeoutError:
                print('Timeout', flush=True)

                pass

            except KeyError:
                continue
            except AttributeError:
                continue
            finally:
                signal.alarm(0)
        if len(new_asts) > 0:
            new_asts=[ast for ast in new_asts if ast[1]<=1]
            new_asts.sort(key=lambda x: x[1])


        new_asts3=[]
        for new_ast in new_asts:
            for n in new_ast[0]:
                new_asts3.append((n,new_ast[5]))

        if len(new_asts) > 0 and self.llm:


            all_count = 0
            equivalent_count = 0
            validated_count = 0
            all_count = len(new_asts)


            new_asts_sorted = new_asts

            equivelent = [False for _ in range(len(new_asts_sorted))]
            for i, ast in enumerate(new_asts_sorted):
                for a in ast[4]:
                    if ast[2] == '':
                        continue
                    if self.get_equivalent_error(a, fullcode, ast[2], idx):
                        equivelent[i] = True
                    else:
                        equivelent[i] = False
            new_asts_sorted = [new_asts_sorted[i] for i in range(len(equivelent)) if equivelent[i]]
            equivalent_count = len(new_asts_sorted)

            if len(new_asts_sorted) > 0:
                validated = [False for _ in range(len(new_asts_sorted))]
                for i, ast in enumerate(new_asts_sorted):
                    for after_ast in ast[0]:
                        if self.flow_checker(before_ast.getCode(), after_ast.getCode(), ast[2], ast[3]):
                            validated[i] = True
                        else:
                            validated[i] = False
                new_asts_sorted = [new_asts_sorted[i] for i in range(len(validated)) if validated[i]]
            validated_count = len(new_asts_sorted)


            print(f"index:{idx} all:{all_count},equivalent:{equivalent_count},validated:{validated_count}")

            for new_ast in new_asts_sorted:
                for n in new_ast[0]:
                    new_asts2.append((n, new_ast[5]))

        else:
            new_asts2 = new_asts3
        return new_asts2, new_asts3

    def find_depth(self, node):
        if not node.children or all(child is None for child in node.children):
            return 1
        return 1 + max(self.find_depth(child) for child in node.children if child is not None)

    def _setPattern2(self):
        single_nodes = []
        tree_rootnode = []
        for i, node in enumerate(self.hierarchical_nodes):
            if self.find_depth(node) > 1:
                tree_rootnode.append(i)
            else:
                single_nodes.append(i)

        single_nodes_pattern = [self.hierarchical_nodes[i] for i in single_nodes]
        single_nodes_pattern_unique = []
        for i, pattern in enumerate(single_nodes_pattern):
            flag = False
            for j in range(i + 1, len(single_nodes_pattern)):
                if pattern.pattern == single_nodes_pattern[j].pattern:
                    flag = True
            if not flag:
                single_nodes_pattern_unique.append(pattern)
        single_nodes_pattern = single_nodes_pattern_unique

        print(len(single_nodes_pattern), len(tree_rootnode), len(self.hierarchical_nodes))
        for root_index in tree_rootnode:
            queue = [self.hierarchical_nodes[root_index]]
            while queue:
                current_node = queue.pop(0)
                if current_node in single_nodes_pattern:
                    single_nodes_pattern.remove(current_node)
                for child in current_node.children:
                    if child is not None:
                        queue.append(child)
        self.hierarchical_nodes = single_nodes_pattern+[self.hierarchical_nodes[i] for i in tree_rootnode]
        print(len(single_nodes_pattern), len(tree_rootnode), len(self.hierarchical_nodes))

    def print_paths(self, node, path=[], allpath=[]):
        path.append(node.pattern.rootcause)
        if not node.children or all(child is None for child in node.children):
            allpath.append(path)
            print(" -> \n".join(path))
            print('='*20)
        else:
            for child in node.children:
                if child is not None:
                    self.print_paths(child, path.copy())

    def backtrack(self, node):
        if not node.children or all(child is None for child in node.children):
            return [node]
        else:
            path = []
            for child in node.children:
                if child is not None:
                    path.extend(self.backtrack(child))
            return path

    def is_child(self, node1, node2):
        while node1.parent is not None:
            if node1.parent.pattern == node2.pattern:
                return True
            node1 = node1.parent
        return False

    def applyPattern2(self, src_tree, rootcause, focus=None, fullcode=None):
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(20)
        before_ast = src_tree
        new_asts = []
        new_asts2 = []
        for node in self.hierarchical_nodes:
            tree_result = []
            queue = deque([node])
            while queue:
                level_size = len(queue)
                level_nodes = []
                for _ in range(level_size):
                    node = queue.popleft()
                    try:
                        new_asts_temp = node.pattern.applyPattern(before_ast, llm=self.llm, focus_statement=focus)
                    except TimeoutError:
                        print('Timeout', flush=True)
                        pass
                    except KeyError:
                        pass
                    except AttributeError:
                        pass
                    finally:
                        signal.alarm(0)
                    if len(new_asts_temp) > 0 and len(new_asts_temp[0]) > 0:
                        level_nodes.append(new_asts_temp)
                    else:
                        level_nodes.append([])
                    for child in node.children:
                        if child is not None:
                            queue.append(child)
                tree_result.append(level_nodes)
            tree_result.reverse()
            tree_flag = False
            for t in tree_result:
                if tree_flag:
                    break
                for ast_temp in t:
                    if len(ast_temp) > 0:
                        new_asts.append(ast_temp)
                        tree_flag = True
                        break

        if len(new_asts) > 0:
            new_asts = [ast for ast in new_asts if ast[1] <= 2]
            new_asts.sort(key=lambda x: x[1])
        if focus is not None and len(new_asts) > 0 and self.llm:
            focuss = '\n'.join(focus)
            rootcause = getRootcause(before_ast.getCode(), focuss)

            all_count = 0
            equivalent_count = 0
            validated_count = 0
            client = Client("http://localhost:9997")

            model_embedding = client.get_model('stella_en_1.5B_v5')
            rootcauses = [ast[2] for ast in new_asts]
            query_embedding = model_embedding.create_embedding(rootcause)
            corpus_embedding = model_embedding.create_embedding(rootcauses)
            corpus_embedding = np.array([embedding['embedding'] for embedding in corpus_embedding['data']])
            query_embedding = np.array([embedding['embedding'] for embedding in query_embedding['data']])
            cosine_similarity = np.dot(query_embedding, corpus_embedding.T)
            cosine_similarity = cosine_similarity.tolist()[0]

            new_asts_sorted = [x for _, x in sorted(zip(cosine_similarity, new_asts), key=lambda pair: pair[0], reverse=True)]
            all_count = len(new_asts_sorted)
            new_asts_sorted = new_asts_sorted[:50]

            model_rerank = client.get_model('reranker')
            query = rootcause
            corpus = [p_root[2] for p_root in new_asts_sorted]
            sort_num = [it['index'] for it in model_rerank.rerank(corpus, query)['results']]


            new_asts_sorted = [new_asts[s] for s in sort_num]
            new_asts_sorted = new_asts_sorted[:10]

            equivelent = []
            for ast in new_asts_sorted:
                if self.get_equivalent_error(ast[4][0], fullcode, ast[2]):
                    equivelent.append(True)
                else:
                    equivelent.append(False)
            new_asts_sorted = [new_asts_sorted[i] for i in range(len(equivelent)) if equivelent[i]]
            equivalent_count = len(new_asts_sorted)

            if len(new_asts_sorted) > 0:
                validated = []
                for ast in new_asts_sorted:
                    if self.get_validated_patch(before_ast.getCode(), ast[0][0].getCode(), ast[2], ast[3]):
                        validated.append(True)
                    else:
                        validated.append(False)
                new_asts_sorted = [new_asts_sorted[i] for i in range(len(validated)) if validated[i]]
            validated_count = len(new_asts_sorted)
            print(f"all:{all_count},equivalent:{equivalent_count},validated:{validated_count}")

        else:
            new_asts_sorted = new_asts
        for new_ast in new_asts_sorted:
            new_asts2.extend(new_ast[0])

        return new_asts2

    def getHoleNum(self, pattern):
        return len(pattern.getBeforeHolesSet())

    def getPatternSize(self, pattern):
        return len(pattern.getBeforePattern())


    def getScore2(self, pattern_score):
        return pattern_score[1]

    def getScore(self, src_tree_pattern):
        if src_tree_pattern[1].hasUnboundHoles() or src_tree_pattern[1].isAmbiguous() or len(
                src_tree_pattern[1].matchAst(src_tree_pattern[0])) == 0:
            return 0
        else:
            return 1


        return s_prevalence * s_specialized


def getRootcause(function, statement):
    client = OpenAI(
        base_url="https://api.deepseek.com",
        api_key=os.getenv("DEEPSEEK_API_KEY", ""),
    )
    prompt = f"""

- Analyze a given code snippet written in C with a statement within the code which potentially contains a security vulnerability.
- Provide a 70-word detailed summary of the statement.
- Your summary should include the root cause of the vulnerability.
- the root cause should contain two insights within one "root_cause" json field: 1. the concrete cause of the vulnerability. 2. the abstract cause of the vulnerability.
- Respond strictly in JSON format as shown below, with no additional commentary.
{{
    "root_cause":"Analyze the causes of errors leading to vulnerabilities, connecting them to the broader task or context of the code while avoiding specific identifier names. Provide an explanation that identifies how the context contributes to the vulnerability"
}}

{function}


{statement}


"""
    prompt_summary = """

- Analyze the following ten vulnerability rootcause sentences to determine which one appears most frequently or has the highest similarity to the others. Consider minor variations in wording or phrasing as similar. Once identified, integrate the most common or similar sentences into one cohesive and concise sentence that best represents their shared meaning. Ensure the resulting sentence is clear, grammatically correct, and conveys the essence of the original ideas.
- Respond strictly in JSON format as shown below, with no additional commentary.
{{
    "common_root_cause":"the most common or similar sentences into one cohesive and concise sentence that best represents their shared meaning. Ensure the resulting sentence is clear, grammatically correct, and conveys the essence of the original ideas."
}}


{}
"""
    rootcauses = []
    for _ in range(1):
        completion = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": "You are an expert in understanding and fixing C language security vulnerabilities."},
                {"role": "user", "content": prompt}
            ],
            temperature=1
        )
        response = completion.choices[0].message.content
        try:
            rootcause = json.loads(response)['root_cause']
            rootcauses.append(rootcause)
        except:
            response = re.search(r"```json(.*?)```", response, re.DOTALL).group(1)
            rootcause = json.loads(response)['root_cause']
            rootcauses.append(rootcause)

    completion = client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {"role": "system", "content": "You are an expert in understanding and fixing C language security vulnerabilities."},
            {"role": "user", "content": prompt_summary.format('\n'.join([f'#Sentence {i}\n{r}\n'for i, r in enumerate(rootcauses)]))}
        ],
        temperature=0
    )
    response = completion.choices[0].message.content
    try:
        rootcause = json.loads(response)['common_root_cause']
    except:
        response = re.search(r"```json(.*?)```", response, re.DOTALL).group(1)
        rootcause = json.loads(response)['common_root_cause']

    return rootcause
