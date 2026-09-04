import copy
from multiprocessing import Manager
import random
import shutil
import signal
import concurrent.futures
import subprocess
import traceback

from openai import OpenAI
import Hierarchical
import pickle
from AST import GumTreeAstPair
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor, as_completed
import csv
import difflib
import gc
import threading
import psutil
import logging
from pympler import asizeof
import os
import sys
import time
import re
import tempfile
csv.field_size_limit(sys.maxsize)
logging.basicConfig(level=logging.ERROR, format='%(asctime)s %(message)s')
MEMORY_MAX_GB = 35


def monitor_all_processes():
    print("monitor_all_processes")
    while True:
        sum_memory = 0
        main_process = psutil.Process(os.getpid())
        child_memory_usages = []
        main_memory_info = main_process.memory_full_info()
        main_memory_usage = main_memory_info.uss / 1024 / 1024 / 1024
        sum_memory += main_memory_usage

        for child in main_process.children(recursive=True):
            try:
                child_memory_info = child.memory_full_info()
                child_memory_usage = child_memory_info.uss / 1024 / 1024 / 1024
                sum_memory += child_memory_usage
                child_memory_usages.append((child, child_memory_usage))
            except psutil.NoSuchProcess:
                pass


        print(f"Total memory usage: {sum_memory:.2f} GB")


        if sum_memory > MEMORY_MAX_GB:
            print(f"Memory usage exceeded {MEMORY_MAX_GB} GB, terminating processes")
            if child_memory_usages:

                child_memory_usages.sort(key=lambda x: x[1], reverse=True)
                try:
                    for c, _ in child_memory_usages:
                        c.kill()
                except:
                    pass
                '''largest_child, largest_child_memory = child_memory_usages[0]
                print(f"Terminating child process {largest_child.pid}, memory usage: {largest_child_memory:.2f} GB")
                largest_child.kill()'''
            else:
                print("No child processes to terminate")


def extract_modified_lines(before, after):
    def diff(before, after):
        lines1 = before.splitlines(keepends=True)
        lines2 = after.splitlines(keepends=True)
        diff = list(difflib.unified_diff(lines1, lines2,
                    fromfile='before', tofile='after', lineterm=''))
        return "".join(diff) if diff else None
    diff_text = diff(before, after)
    lines = diff_text.split('\n')
    modified_lines = []
    for i, line in enumerate(lines):
        if line.startswith('+') and not line.startswith('+++'):
            if i > 0 and not lines[i-1].startswith('+'):
                modified_lines.append(lines[i-1])
            if i < len(lines) - 1 and not lines[i+1].startswith('+') and not lines[i+1].startswith('+++'):
                modified_lines.append(lines[i+1])
        elif line.startswith('-') and not line.startswith('---'):
            modified_lines.append(line)
    return modified_lines


def timeout_handler(signum, frame):
    raise TimeoutError("Timeout")


def format_code(code, language):
    if language == 'c':
        with tempfile.NamedTemporaryFile(mode='w+', delete=True, suffix=".c") as beforefile:
            beforefile.write(code)
            beforefile.flush()
            command_format = ['clang-format', beforefile.name]
            result = subprocess.run(command_format, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            formatted_code = result.stdout

        return formatted_code.strip('\n').strip()

def handleRow(r, i, focus=False):
    try:
        pair = GumTreeAstPair(r[0], r[1], str(i), language=language)
        before_ast = pair.getBeforeAst()
        after_ast = pair.getAfterAst()

        new_ast_dir = f'../results/codes/{i}'
        try:
            shutil.rmtree(new_ast_dir)
        except:
            pass
        os.makedirs(new_ast_dir, exist_ok=True)
        after_ast_code = after_ast.getCode()
        before_ast_code = before_ast.getCode()
        new_ast_path = os.path.join(new_ast_dir, '_truth.c')
        new_ast_path_before = os.path.join(new_ast_dir, '_before.c')
        formatted_code = format_code(after_ast_code, language)
        formatted_code_before = format_code(before_ast_code, language)
        with open(new_ast_path_before, 'w') as new_ast_file:
            new_ast_file.write(formatted_code_before)
        with open(new_ast_path, 'w') as new_ast_file:
            new_ast_file.write(formatted_code)

        if not focus:
            new_asts, all_new_asts = hierarchical_cluster.applyPattern(before_ast, pair.idx, fullcode=r[0])
        else:
            new_asts, all_new_asts = hierarchical_cluster.applyPattern(before_ast, pair.idx, r[2].split('#$%^'), fullcode=r[0])

    except TimeoutError:
        print('Timeout')
        return (None, None, None, i, None, None)
    except Exception:
        traceback.print_exc()
        return (None, None, None, i, None, None)
    flag = False
    flag_any = False
    all_flag = False
    try:
        for ppp in range(len(new_asts)):
            new_ast = new_asts[ppp][0]
            if new_ast.getCode() == after_ast.getCode():
                flag = True
                flag_any = True
            else:
                flag = False
            new_ast_code = new_ast.getCode()
            new_ast_path = os.path.join(new_ast_dir, f'{ppp}_{flag}.c')
            formatted_code = format_code(new_ast_code, language)
            with open(new_ast_path, 'w') as new_ast_file:
                new_ast_file.write(formatted_code+'\n'+new_asts[ppp][1])

        for ppp in range(len(all_new_asts)):
            new_ast = all_new_asts[ppp][0]
            if new_ast.getCode() == after_ast.getCode():
                all_flag = True
                break
            else:
                all_flag = False
    except:
        traceback.print_exc()
        return (None, None, None, i, None, None)


    length_ast = str(len(new_asts))
    del new_asts
    return (pair.idx, "success_llm-----" if flag_any else 'fail_llm------', length_ast, i, "success_all" if all_flag else 'fail_all', str(len(all_new_asts)))


def deal_with_rag(vul, vulstatement):
    client = OpenAI(
        base_url="https://api.deepseek.com",
        api_key=os.getenv("DEEPSEEK_API_KEY", ""),
    )
    prompt = f"""
You are a C code expert.
You are given a C code snippet with a vulnerability and the most likely location of the vulnerability. Your task is to provide a fix for the vulnerability.
Please provide the fixed code snippet in C and a brief explanation of the changes made to fix the vulnerability. And separate the code and explanation with '=============='.
No comments are needed. You can modity, delete or add code to fix the vulnerability.

{vul}


{vulstatement}


"""
    completion = client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {"role": "user", "content": prompt}
        ],
        temperature=0
    )
    response = completion.choices[0].message.content

    pattern = r'```c(.*?)```'
    try:
        matches = re.findall(pattern, response, re.DOTALL)
        if matches:
            fixed_code = matches[0].strip()
        else:
            fixed_code = ""
    except:
        fixed_code = ""
    return fixed_code


def testPairs3(path):
    with open(path, 'r') as testfile, open('../results/result.csv', 'w') as resultfile:
        reader = csv.reader(testfile)
        writer = csv.writer(resultfile)
        rows = []
        batch = 64
        for r in reader:
            rows.append(r)
        process_tasks(rows, writer, resultfile, handleRow, batch)

def input_monitor():
    print("Enter 'r' to rebuild process pool:\n\n ", flush=True)
    while True:
        main_process = psutil.Process(os.getpid())
        child_memory_usages = []
        for child in main_process.children(recursive=True):
            try:
                child_memory_usages.append((child, 0))
            except psutil.NoSuchProcess:
                pass
        user_input = input()
        if user_input.lower() == 'r':
            print("\nReceived rebuild command, preparing to rebuild process pool...")
            if child_memory_usages:
                child_memory_usages.sort(key=lambda x: x[1], reverse=True)
                try:
                    for c, _ in child_memory_usages:
                        c.kill()
                except:
                    pass
            else:
                print("No child processes to terminate")

def process_tasks(rows, writer, resultfile, handleRow, batch=10):
    row_pointer = [0 for _ in range(len(rows))]
    finished_count = [0 for _ in range(len(rows))]
    endflag = [False]

    def execute_tasks(executor, row_pointer, finished_count, endflag, pbar):

        futures = []
        row_pointer = copy.deepcopy(finished_count)
        while not endflag[0]:
            try:
                pass
            except concurrent.futures.process.BrokenProcessPool:
                print("Process pool interrupted, will rebuild at outer level...")
                return

            if (0 not in row_pointer) and len(futures) == 0:
                if (0 not in finished_count):
                    endflag[0] = True
                else:
                    print(finished_count)
                    return

            while len(futures) < batch and 0 in row_pointer:
                zero_indices = [index for index, value in enumerate(row_pointer) if value == 0]

                if zero_indices:
                    task_index = random.choice(zero_indices)
                else:
                    task_index = None

                try:
                    futures.append(executor.submit(handleRow, rows[task_index], task_index, focus))
                except concurrent.futures.process.BrokenProcessPool as exc:
                    return
                row_pointer[task_index] = 1
            completed_futures = [fut for fut in futures if fut.done()]
            for future in completed_futures:
                try:
                    r1, r2, r3, idx, r4, r5 = future.result()
                    if (r1 is not None and int(r3) > 0) or (r1 is not None and 'success' in r2) or (r1 is not None and 'success' in r4):
                        writer.writerow((r1, r2, r3, r5, r4))
                    resultfile.flush()
                    pbar.update(1)
                    finished_count[idx] = 1

                except IndexError as exc:
                    logging.error(f"Error occurred while processing pair: {exc}")
                    finished_count[idx] = 1
                except concurrent.futures.process.BrokenProcessPool as exc:
                    logging.error(f"Error: BrokenProcessPool")
                    return

                except Exception as exc:
                    traceback.print_exc()
                    finished_count[idx] = 1
                finally:
                    futures.remove(future)
    with tqdm(total=len(rows), desc="Processing Test Tasks", unit="unit") as pbar:
        maxworkers = 4
        while not endflag[0]:
            monitor_thread = threading.Thread(target=monitor_all_processes, daemon=True)
            monitor_thread.start()
            input_thread = threading.Thread(target=input_monitor, daemon=True)
            input_thread.start()

            executor = ProcessPoolExecutor(max_workers=maxworkers)
            execute_tasks(executor, row_pointer, finished_count, endflag, pbar)
            maxworkers = max(maxworkers//2, 4)
    logging.info("All tasks processed successfully.")


llm = False
focus = False
language = 'c'
island_only = False
include = False
include_type = [type+'_cluster.pkl' for type in ['expr_stmt','if_stmt','for','goto','else','while','decl_stmt','do','init']]
cluster_path = './clusters/'
test_path = '../datasets/ICVul/processed_vulnerabilities.csv'

btime = time.time()
hierarchical_cluster = Hierarchical.HierarchicalCluster([], llm=llm)
clusters = os.listdir(cluster_path)
for cluster in clusters:
    f = open(cluster_path + cluster, 'rb')
    try:
        if include:
            if cluster not in include_type:
                print(f"Skip {cluster}")
                continue
        if island_only:
            if 'addition' not in cluster:
                print(f"Skip {cluster}")
                continue
        hierarchical_cluster.hierarchical_nodes.extend(pickle.load(f))
    except:
        traceback.print_exc()
        pass
    f.close()
f = open('./pkls/' + 'block_content.pkl', 'rb')
hierarchical_cluster.hierarchical_nodes.extend(pickle.load(f))

hierarchical_cluster._setPattern()
atime = time.time()
print('pattern init time:', atime-btime)

results_codes_dir = '../results/codes'
if os.path.exists(results_codes_dir):
    shutil.rmtree(results_codes_dir)
    print(f"Deleted directory: {results_codes_dir}")
os.makedirs(results_codes_dir, exist_ok=True)
print(f"Created new directory: {results_codes_dir}")

testPairs3(test_path)
