import copy
import difflib
import os
import subprocess
import tempfile
import traceback
from openai import OpenAI
import json


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


class GumTreeAstPair:
    def __init__(self, before, after, idx, language='c'):
        self.idx = idx
        self.__before_ast = None
        self.__after_ast = None
        self.__before_code = None
        self.__after_code = None
        self.__code_map = {}
        self.__diff_nodes_info = []
        self.__node_map = {}
        self.__reversed_node_map = {}
        self.__deleted_trees = set()

        self.__updated_nodes = set()
        self.__inserted_trees = set()
        self.__modified_before_trees = set()
        self.language = language


        self.__parsePair(before, after)

    def remove_double_newlines(self, content):
        cleaned_lines = []
        previous_line_blank = False
        for line in content:
            if line.strip() == '':
                if not previous_line_blank:
                    cleaned_lines.append(line)
                previous_line_blank = True
            else:
                cleaned_lines.append(line)
                previous_line_blank = False
        return cleaned_lines

    def __parsePair(self, before, after):
        assert before != ""
        assert after != ""
        if self.language == 'java':
            suffix = '.java'
        elif self.language == 'c':
            suffix = '.c'
        elif self.language == 'python':
            suffix = '.py'
        beforefile = tempfile.NamedTemporaryFile(mode='w+', delete=True, suffix=suffix)
        afterfile = tempfile.NamedTemporaryFile(mode='w+', delete=True, suffix=suffix)
        temp_beforefile = tempfile.NamedTemporaryFile(mode='w+', delete=True, suffix=suffix)
        temp_afterfile = tempfile.NamedTemporaryFile(mode='w+', delete=True, suffix=suffix)
        if before != None:
            beforefile.write(before)
            beforefile.flush()
            if self.language == 'c':

                command_format = ['gcc', '-fpreprocessed', '-dD', '-E', '-P', beforefile.name]
            elif self.language == 'java':
                command_format = ['clang-format', "-style={ColumnLimit: 150}", beforefile.name]
            result = subprocess.run(command_format, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            formated_code = result.stdout
            self.__before_code = formated_code
            beforefile.close()
            temp_beforefile.write(formated_code)
            temp_beforefile.flush()


            if self.language == 'c':
                command_parse = ['gumtree', 'parse', '-g', 'c-srcml', temp_beforefile.name]
            elif self.language == 'java':
                command_parse = ['gumtree', 'parse', '-g', 'c-srcml', temp_beforefile.name]
            result = subprocess.run(command_parse, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            before_ast_lines = result.stdout.split('\n')
            self.__before_ast = GumTreeAst(before_ast_lines, self.__before_code, self.language)

        if after != None:
            afterfile.write(after)
            afterfile.flush()
            if self.language == 'c':

                command_format = ['gcc', '-fpreprocessed', '-dD', '-E', '-P', afterfile.name]
            elif self.language == 'java':
                command_format = ['clang-format', "-style={ColumnLimit: 150}", afterfile.name]
            result = subprocess.run(command_format, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            formated_code = result.stdout
            self.__after_code = formated_code
            afterfile.close()
            temp_afterfile.write(formated_code)
            temp_afterfile.flush()
            if self.language == 'c':
                command_parse = ['gumtree', 'parse', '-g', 'c-srcml', temp_afterfile.name]
            elif self.language == 'java':
                command_parse = ['gumtree', 'parse', '-g', 'c-srcml', temp_afterfile.name]
            result = subprocess.run(command_parse, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            after_ast_lines = result.stdout.split('\n')

            self.__after_ast = GumTreeAst(after_ast_lines, self.__after_code, self.language)

        if self.language == 'java':
            command = ['gumtree', 'textdiff',  temp_beforefile.name, temp_afterfile.name, '-f', 'JSON']
        elif self.language == 'c':
            command = ['gumtree', 'textdiff', '-g', 'c-srcml',  temp_beforefile.name, temp_afterfile.name, '-f', 'JSON']
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
            result, stderr = process.communicate()


            f_diff = result
        temp_beforefile.close()
        temp_afterfile.close()


        self.__diff_nodes_info = json.loads(f_diff)
        i = 1
        for match in self.__diff_nodes_info['matches']:
            before_node_info = match['src'].split(' ')
            after_node_info = match['dest'].split(' ')
            if len(before_node_info) >= 3:

                before_node_location = before_node_info[0][:-1] + " " + before_node_info[-1]
            else:
                before_node_location = before_node_info[0] + " " + before_node_info[1]
            if len(after_node_info) >= 3:

                after_node_location = after_node_info[0][:-1] + " " + after_node_info[-1]
            else:
                after_node_location = after_node_info[0] + " " + after_node_info[1]
            before_node_id = self.__before_ast.getNodeByLocation(before_node_location).getIdInAst()
            after_node_id = self.__after_ast.getNodeByLocation(after_node_location).getIdInAst()
            self.__node_map[before_node_id] = after_node_id
            self.__reversed_node_map[after_node_id] = before_node_id

        for action in self.__diff_nodes_info['actions']:
            if 'delete' in action['action']:
                before_node_info = action['tree'].split(' ')
                if len(before_node_info) >= 3:

                    before_node_location = before_node_info[0][:-1] + " " + before_node_info[-1]
                else:
                    before_node_location = before_node_info[0] + " " + before_node_info[1]
                before_node = self.__before_ast.getNodeByLocation(before_node_location)
                before_node_id = before_node.getIdInAst()
                self.__deleted_trees.add(before_node_id)
                self.__modified_before_trees.add(before_node_id)
                cur_node = before_node
                while cur_node.parent != None:

                    self.__modified_before_trees.add(cur_node.parent.getIdInAst())
                    cur_node = cur_node.parent
            if "insert" in action['action']:
                after_node_info = action['tree'].split(' ')
                if len(after_node_info) >= 3:

                    after_node_location = after_node_info[0][:-1] + " " + after_node_info[-1]
                else:
                    after_node_location = after_node_info[0] + " " + after_node_info[1]
                after_node = self.__after_ast.getNodeByLocation(after_node_location)
                after_node_id = after_node.getIdInAst()
                self.__inserted_trees.add(after_node_id)
                cur_node = after_node

                if cur_node.parent != None:
                    for cc, child in enumerate(cur_node.parent.children):
                        if child == cur_node:
                            child_location = cc
                    if cur_node.parent.getIdInAst() in self.__reversed_node_map:
                        if child_location+1 <len(cur_node.parent.children)  and cur_node.parent.children[child_location+1].getIdInAst() in self.__reversed_node_map:
                            self.__modified_before_trees.add(self.__reversed_node_map[cur_node.parent.children[child_location+1].getIdInAst()])
                        else:
                            self.__modified_before_trees.add(self.__reversed_node_map[cur_node.parent.getIdInAst()])


            if "update" in action['action']:
                before_node_info = action['tree'].split(' ')
                if len(before_node_info) >= 3:
                    before_node_location = before_node_info[0][:-1] + " " + before_node_info[-1]
                else:
                    before_node_location = before_node_info[0] + " " + before_node_info[1]
                before_node = self.__before_ast.getNodeByLocation(before_node_location)
                before_node_id = self.__before_ast.getNodeByLocation(before_node_location).getIdInAst()
                self.__updated_nodes.add(before_node_id)
                self.__modified_before_trees.add(before_node_id)
                cur_node = before_node
                while cur_node.parent != None:

                    self.__modified_before_trees.add(cur_node.parent.getIdInAst())
                    cur_node = cur_node.parent
            if "move" in action['action']:
                before_node_info = action['tree'].split(' ')
                if len(before_node_info) >= 3:
                    before_node_location = before_node_info[0][:-1] + " " + before_node_info[-1]
                else:
                    before_node_location = before_node_info[0] + " " + before_node_info[1]
                before_node = self.__before_ast.getNodeByLocation(before_node_location)

                def markUpdatedNode(before_node):
                    before_node_id = before_node.getIdInAst()
                    self.__deleted_trees.add(before_node_id)
                    self.__modified_before_trees.add(before_node_id)
                    if before_node_id in self.__node_map:
                        after_node_id = self.__node_map[before_node_id]
                        self.__inserted_trees.add(after_node_id)
                    cur_node = before_node
                    while cur_node.parent != None:
                        self.__modified_before_trees.add(cur_node.parent.getIdInAst())
                        cur_node = cur_node.parent
                    for child in before_node.children:
                        markUpdatedNode(child)


                markUpdatedNode(before_node)


    def getBeforeAst(self):
        return self.__before_ast


    def getAfterAst(self):
        return self.__after_ast


    def getNodeMap(self):
        return_map = copy.deepcopy(self.__node_map)
        return return_map

    def getReversedNodeMap(self):
        return_map = copy.deepcopy(self.__reversed_node_map)
        return return_map

    def getInsertedTrees(self):
        return_set = copy.deepcopy(self.__inserted_trees)
        return return_set

    def getDeletedTrees(self):
        return_set = copy.deepcopy(self.__deleted_trees)
        return return_set

    def getUpdatedNodes(self):
        return_set = copy.deepcopy(self.__updated_nodes)
        return return_set

    def getModifiedBeforeTrees(self):
        return_set = copy.deepcopy(self.__modified_before_trees)
        return return_set

    '''
    def isSubtreeModified2(self, subtree_root_node_id):
        subtree_root_node = self.__before_ast.getNodeDict()[subtree_root_node_id]
        if subtree_root_node.getIdInAst() in self.__updated_nodes or subtree_root_node.getIdInAst() in self.__deleted_trees:
            return True
        for child in subtree_root_node.children:
            if self.isSubtreeModified2(child.getIdInAst()):
                return True
        return False

    def isSubtreeModified(self, subtree_root_node_id):
        subtree_root_node = self.__before_ast.getNodeDict()[subtree_root_node_id]
        if subtree_root_node.getIdInAst() in self.__updated_nodes or subtree_root_node.getIdInAst() in self.__deleted_trees:
            return True
        for child in subtree_root_node.children:
            if self.isSubtreeModified2(child.getIdInAst()):
                return True
        if not subtree_root_node_id in self.__node_map:
            return True
        after_subtree_root_node_id = self.__node_map[subtree_root_node_id]
        if self.isAfterSubtreeInserted(after_subtree_root_node_id):
            return True
        return False

    def isAfterSubtreeInserted(self, subtree_root_node_id):
        subtree_root_node = self.__after_ast.getNodeDict()[subtree_root_node_id]
        if subtree_root_node.getIdInAst() in self.__inserted_trees:
            return True
        for child in subtree_root_node.children:
            if self.isAfterSubtreeInserted(child.getIdInAst()):
                return True
        return False
    '''


class GumTreeAstType:
    def __init__(self, type_name):
        self.type_name = type_name


    def __eq__(self, other):
        if type(self) != type(other):
            return False
        return self.type_name == other.type_name


class GumTreeAstNode:
    def __init__(self, AST=None, id_in_ast=-1, code=''):

        self.__AST = AST
        self.__id_in_ast = id_in_ast

        self.type = None
        self.value = ''
        self.children = []
        self.parent = None
        self.code = code

        self.location = ''

    def getAst(self):
        return self.__AST

    def getIdInAst(self):
        return self.__id_in_ast

    def setIdInAst(self, id_in_ast):
        self.__id_in_ast = id_in_ast

    def getCode(self):
        return self.code

    def __str__(self):
        string = "id: " + str(self.__id_in_ast) + "\ntype: " + self.type.type_name + "\nvalue: " + self.value + "\n children:" + "[ "
        for child in self.children:
            string = string + str(child.getIdInAst()) + ' '
        string = string + ']\nparent: '
        if self.parent != None:
            string = string + str(self.parent.getIdInAst())
        string = string + '\nlocation: ' + self.location
        return string

    def __eq__(self, other):
        if type(other) != type(self):
            return False
        if self.type != other.type or self.value != other.value:
            return False
        if len(self.children) != len(other.children):
            return False
        for i in range(len(self.children)):
            if self.children[i] != other.children[i]:
                return False
        return True


class GumTreeAst:
    def __init__(self, file_lines, code='', language='c'):
        self.__root_node = None
        self.__node_dict = {}
        self.__node_dict_by_location = {}

        self.__new_idx = 0
        self.__code = code
        self.language = language
        self.__readAst(file_lines)

    def __eq__(self, other):
        return self.__root_node == other.__root_node

    def size(self):
        return len(self.__node_dict)

    def __len__(self):
        return self.size()

    def addRootNode(self, type, value):
        if self.__root_node == None:
            self.__root_node = GumTreeAstNode(self, self.__new_idx)
            self.__root_node.type = type
            self.__root_node.value = value
            self.__node_dict[self.__new_idx] = self.__root_node
            parent_node_id = self.__new_idx
            self.__new_idx += 1

    def getRootNode(self):

        return_node = self.__root_node
        return return_node

    def getNodeDict(self):

        return_dict = self.__node_dict
        return return_dict

    def getNodeById(self, id):
        return_node = self.__node_dict[id]
        return return_node

    def getNodeByLocation(self, location):


        return_node = self.__node_dict_by_location[location]
        return return_node

    def addSingleNode(self, type, value, parent_node_id, children_list_location, location='', node_code=''):
        new_node = GumTreeAstNode(self, self.__new_idx)
        new_node.type = type
        new_node.value = value
        new_node.children = []
        new_node.parent = self.__node_dict[parent_node_id]
        new_node.location = location
        new_node.code = node_code
        self.__node_dict[parent_node_id].children.insert(children_list_location, new_node)
        self.__node_dict[self.__new_idx] = new_node
        self.__node_dict_by_location[new_node.type.type_name + " " + new_node.location] = new_node
        self.__new_idx += 1
        return self.__new_idx - 1

    def getSubtree(self, subtree_root_node_id, node_map={}):
        node_map[0] = subtree_root_node_id
        ret_subtree = GumTreeAst([], self.getNodeById(subtree_root_node_id).getCode())
        ret_subtree.__root_node = GumTreeAstNode(ret_subtree, ret_subtree.__new_idx)
        src_subtree_root_node = self.__node_dict[subtree_root_node_id]
        ret_subtree.__root_node.type = src_subtree_root_node.type
        ret_subtree.__root_node.value = src_subtree_root_node.value
        ret_subtree.__node_dict[ret_subtree.__new_idx] = ret_subtree.__root_node
        ret_subtree.__new_idx += 1
        for i, child in enumerate(src_subtree_root_node.children):
            self.copySubtree(child, ret_subtree, ret_subtree.__root_node.getIdInAst(), i, node_map)
        return ret_subtree

    def copySubtree(self, src_subtree_root_node, tgt_tree, tgt_subtree_parent_node_id,
                    tgt_subtree_children_list_location, node_map={}):
        new_node_id = tgt_tree.addSingleNode(src_subtree_root_node.type, src_subtree_root_node.value,
                                             tgt_subtree_parent_node_id, tgt_subtree_children_list_location)
        node_map[new_node_id] = src_subtree_root_node.getIdInAst()
        for i, child in enumerate(src_subtree_root_node.children):
            self.copySubtree(child, tgt_tree, new_node_id, i, node_map)

    def __str__(self):
        if self.__root_node == None:
            return ""
        return self.printSubtree(self.__root_node, 0)

    def printSubtree(self, subtree_root_node, depth):
        string = " " * depth + str(subtree_root_node.getIdInAst()) + ": " + subtree_root_node.type.type_name + ": " + subtree_root_node.value + "\n"


        for child in subtree_root_node.children:
            string = string + self.printSubtree(child, depth + 1)

        return string

    def getHoppityAst(self):
        try:
            tmp = self.type_dict
        except:
            f = open('./type_dict.json')
            self.type_dict = json.load(f)
            f.close()

        obj = {}
        obj["type"] = "Module"
        obj["directives"] = []
        obj["items"] = []
        root_node = self.getRootNode()
        if root_node.type.type_name == 'unit':
            obj["idx"] = 0
            children = root_node.children
            for child in children:
                self.__getHoppityAstHelper(child, obj["items"], True)
        else:
            obj["idx"] = -1
            self.__getHoppityAstHelper(root_node, obj["items"], True)
        return obj

    def __getHoppityAstHelper(self, subtree_root_node, obj, is_list):
        new_obj = {}
        if not is_list:
            new_obj = obj
        new_obj["type"] = subtree_root_node.type.type_name
        new_obj["idx"] = subtree_root_node.getIdInAst()
        if new_obj["type"] in self.type_dict and len(self.type_dict[new_obj["type"]]) == 1:
            fields = self.type_dict[new_obj["type"]][0]
            for i, field in enumerate(fields):
                field_name = ""
                for j, t in enumerate(field):
                    if j == 0:
                        field_name = field_name + t.upper()
                    elif j > 0 and field[j - 1] == '_':
                        field_name = field_name + t.upper()
                    else:
                        field_name = field_name + t
                new_obj[field_name] = {}
                child = subtree_root_node.children[i]
                self.__getHoppityAstHelper(child, new_obj[field_name], False)
            if len(fields) == 0:
                new_obj["Token"] = {}
                new_obj["Token"]["type"] = "SyntaxToken"
                new_obj["Token"]["value"] = subtree_root_node.value

        else:
            new_obj[subtree_root_node.type.type_name + "List"] = []
            for child in subtree_root_node.children:
                self.__getHoppityAstHelper(
                    child, new_obj[subtree_root_node.type.type_name + "List"], True)
            if len(subtree_root_node.children) == 0:
                new_obj[subtree_root_node.type.type_name + "List"] = {}
                new_token = new_obj[subtree_root_node.type.type_name + "List"]
                new_token["type"] = "SyntaxToken"
                new_token["value"] = subtree_root_node.value


        if is_list:
            obj.append(new_obj)

    def getLastIdxInSubtree(self, node):
        curidx = node.getIdInAst()
        maxidx = curidx
        for child in node.children:
            maxidx = max(maxidx, self.getLastIdxInSubtree(child))
        return maxidx

    def deleteChildren(self, node):
        updateidx = []
        parentidx = node.getIdInAst()
        lastidx = self.getLastIdxInSubtree(node)
        gap = lastidx-parentidx
        for i, child in enumerate(node.children):
            del node.children[i]
        for k in self.__node_dict:
            if k > lastidx:
                updateidx.append(k)
        for c in range(parentidx+1, lastidx+1):
            self.__node_dict.pop(c)
        for idx in updateidx:
            self.__node_dict[idx].setIdInAst(idx-gap)
            self.__node_dict[idx-gap] = self.__node_dict.pop(idx)

    def deleteSiblings(self, nodes):
        if len(nodes) == 0:
            return
        updateidx = []
        parent = self.__node_dict[nodes[0]].parent
        lastidx = len(nodes)-1
        startidx = nodes[0]
        gap = lastidx - startidx + 1
        for i, child in enumerate(parent.children):
            if child.getIdInAst() in nodes:
                del parent.children[i]
        for k in self.__node_dict:
            if k > lastidx:
                updateidx.append(k)
        for c in range(startidx, lastidx + 1):
            self.__node_dict.pop(c)
        for idx in updateidx:
            self.__node_dict[idx].setIdInAst(idx-gap)
            self.__node_dict[idx-gap] = self.__node_dict.pop(idx)


    def getCode(self, mark=None):
        if self.language == 'c':
            return self.CgetCode(mark)
        if self.language == 'java':
            return self.javaGetCode(mark)

    def CgetCode(self, mark=None):
        preprocessor_directives = {
            'ifdef', 'ifndef', 'endif', 'else', 'define',
            'include', 'pragma', 'error', 'warning', 'line'
        }
        pattern_text = self.__str__()
        lines = pattern_text.split("\n")
        code = ""
        stack = []
        prev_node_type = ""
        ternary_flag = False
        do_flag = False
        prev_indent = 0
        for iii, line in enumerate(lines):
            if iii == mark:
                code = code + "/*target_line*/"
            indent = 0
            for i, t in enumerate(line):
                if t != " ":
                    indent = i
                    break
            while len(stack) > 0 and indent <= stack[-1][0]:
                code = code + stack[-1][1] + " "
                stack.pop()
            split_line = line.split(":")
            node_type = ""
            if len(split_line) > 1:
                node_type = split_line[1][1:]

            if node_type == "parameter_list":
                code = code + "( "
                stack.append([indent, ")"])

            if node_type == "argument_list":
                code = code + "( "
                stack.append([indent, ")"])

            if node_type == "block":
                if do_flag:
                    code = code + "{ "
                    stack.append([indent, "} while"])
                    do_flag = False
                code = code + "{ "
                stack.append([indent, "}"])

            if node_type == "index":
                code = code + "[ "
                stack.append([indent, "]"])

            if node_type == "ternary":
                ternary_flag = True

            if node_type == "condition" and prev_indent < indent and prev_node_type != "ternary":
                code = code + "( "
                stack.append([indent, ")"])

            if node_type == "condition" and prev_indent >= indent:
                stack.append([indent, ";"])

            if node_type == "then":
                code = code + "?"

            if node_type == "control":
                code = code + "( "
                stack.append([indent, ")"])

            if node_type == "decl_stmt":
                stack.append([indent, ";"])

            if node_type == "expr_stmt":
                stack.append([indent, ";"])

            if node_type == "if":
                code = code + "if "

            if node_type == "continue":
                code = code + "continue ; "

            if node_type == "while":
                code = code + "while "

            if node_type == "do":
                code = code + "do "
                do_flag = True

            if node_type == "switch":
                code = code + "switch "

            if node_type == "case":
                code = code + "case "
                stack.append([indent, ":"])

            if node_type == "break":
                code = code + "break ; "

            if node_type == "default":
                code = code + "default : "

            if node_type == "sizeof":
                code = code + "sizeof "

            if node_type == "else" and ternary_flag == False:
                code = code + "else "

            if node_type == "else" and ternary_flag == True:
                code = code + ": "
                ternary_flag = False

            if node_type == "for":
                code = code + "for "
            if node_type == "return":
                code = code + "return "
                stack.append([indent, ";"])

            if node_type == "init" and prev_indent == indent:
                code = code + "= "

            if node_type == "init" and prev_indent != indent:
                stack.append([indent, ";"])

            if node_type == "parameter" and indent <= prev_indent and indent != 0:
                code = code + ", "

            if node_type == "argument" and indent <= prev_indent and indent != 0:
                code = code + ", "

            if node_type == "decl" and indent <= prev_indent and indent != 0:
                code = code + ", "

            token = ""
            if len(split_line) > 2:
                colon_num = 0
                for i, t in enumerate(line):
                    if t == ":":
                        colon_num += 1
                    if colon_num == 2:
                        token = line[i + 2:]
                        break
            if token != "":
                if token in preprocessor_directives:
                    code = code + f"#{token} "
                else:
                    code = code + token + " "
            prev_node_type = node_type
            prev_indent = indent
        return code

    def javaGetCode(self, mark=None):
        pattern_text = self.__str__()
        lines = pattern_text.split("\n")
        code = ""
        stack = []
        prev_node_type = ""
        ternary_flag = False
        lambda_flag = False
        do_flag = False
        class_flag = False
        return_lambda_flag = False
        prev_indent = 0
        generic_indent = 0
        generic_indent_type = 0
        generic_indent_constructor = 0
        generic_indent_implements = 0
        generic_flag = False
        generic_flag_type = False
        generic_flag_constructor = False
        generic_flag_implements = False
        final_return = ''
        for iii, line in enumerate(lines):
            if iii == mark:
                code = code + "/*target_line*/"
            indent = 0
            for i, t in enumerate(line):
                if t != " ":
                    indent = i
                    break
            while len(stack) > 0 and indent <= stack[-1][0]:

                code = code + stack[-1][1] + " "
                final_return = stack[-1][1]
                if stack[-1][1] == ') ->':
                    lambda_flag = True
                stack.pop()

            split_line = line.split(":")
            node_type = ""
            if len(split_line) > 1:
                node_type = split_line[1][1:]

            if node_type == "parameter_list":
                if lambda_flag == True:
                    code = code + "( "
                    stack.append([indent, ") ->"])
                    lambda_flag = False
                elif generic_flag and indent == generic_indent+2:
                    code = code + "< "
                    stack.append([indent, ">"])
                    generic_flag = False
                elif generic_flag_constructor and indent == generic_indent_constructor+1:
                    code = code + "< "
                    stack.append([indent, ">"])
                    generic_flag_constructor = False
                elif generic_flag_type:
                    code = code + "< "
                    stack.append([indent, ">"])
                elif generic_flag_implements:
                    code = code + "< "
                    stack.append([indent, ">"])
                else:
                    code = code + "( "
                    stack.append([indent, ")"])

            if node_type == "argument_list":
                if generic_flag and indent == generic_indent+2:
                    code = code + "< "
                    stack.append([indent, ">"])
                    generic_flag = False
                elif generic_flag_type:
                    code = code + "< "
                    stack.append([indent, ">"])
                elif generic_flag_implements:
                    code = code + "< "
                    stack.append([indent, ">"])
                else:
                    code = code + "( "
                    stack.append([indent, ")"])

            if node_type == "block":
                if do_flag:
                    code = code + "{ "
                    stack.append([indent, "} while"])
                    do_flag = False
                elif lambda_flag:
                    if return_lambda_flag:
                        code = code + "{ "
                        stack.append([indent, "}"])
                        return_lambda_flag = False
                    else:
                        pass
                    lambda_flag = False
                else:
                    code = code + "{ "
                    stack.append([indent, "}"])

            if node_type == "index":
                code = code + "[ "
                stack.append([indent, "]"])

            if node_type == "ternary":
                ternary_flag = True

            if node_type == "condition" and prev_indent < indent and prev_node_type != "ternary":
                code = code + "( "
                stack.append([indent, ")"])

            if node_type == "condition" and prev_indent >= indent and prev_node_type != "ternary" and final_return == '} while ':
                code = code + "( "
                stack.append([indent, ";"])
                stack.append([indent, ")"])

            if node_type == "condition" and prev_indent >= indent and final_return != '} while ':
                stack.append([indent, ";"])

            if node_type == "then":
                code = code + "?"

            if node_type == "control":
                code = code + "( "
                stack.append([indent, ")"])

            if node_type == "decl_stmt":
                stack.append([indent, ";"])

            if node_type == "expr_stmt":
                stack.append([indent, ";"])

            if node_type == "if":
                code = code + "if "

            if node_type == "continue":
                code = code + "continue ; "

            if node_type == "while":
                code = code + "while "

            if node_type == "switch":
                code = code + "switch "

            if node_type == "case":
                code = code + "case "
                stack.append([indent, ":"])

            if node_type == "break":
                code = code + "break ; "

            if node_type == "default":
                code = code + "default : "

            if node_type == "else" and ternary_flag == False:
                code = code + "else "

            if node_type == "else" and ternary_flag == True:
                code = code + ": "
                ternary_flag = False

            if node_type == "for":
                code = code + "for "

            if node_type == "return":
                code = code + "return "
                stack.append([indent, ";"])

            if node_type == "init" and prev_indent == indent:
                code = code + "= "
            if node_type == "init" and prev_indent != indent:
                if prev_node_type != 'control':
                    stack.append([indent, ";"])

            if node_type == "parameter" and indent <= prev_indent and indent != 0:
                code = code + ", "

            if node_type == "argument" and indent <= prev_indent and indent != 0:
                code = code + ", "

            if node_type == "decl" and indent <= prev_indent and indent != 0:
                code = code + ", "


            if node_type == 'constructor':
                generic_flag_constructor = True
                generic_flag = False
                generic_indent_constructor = indent

            if node_type == 'name':
                if indent == generic_indent_constructor+1:
                    generic_flag_constructor = False

            if node_type == 'class' or node_type == 'interface' or node_type == 'call':
                generic_flag = True
                generic_flag_constructor = False
                generic_indent = indent

            if generic_indent_type == indent:
                generic_flag_type = False
            if node_type == 'type':
                generic_flag = False
                generic_flag_type = True
                generic_flag_constructor = False
                generic_indent_type = indent

            if generic_indent_implements == indent:
                generic_flag_implements = False
            if node_type == 'implements':
                generic_flag = False
                generic_flag_implements = True
                generic_flag_constructor = False
                generic_indent_implements = indent

            if node_type == 'range':
                code = code + ": "

            if node_type != "specifier" and class_flag:
                code = code + stack[-1][1]+' '
                final_return = stack[-1][1]
                stack.pop()
                class_flag = False

            if node_type == "function_decl":
                stack.append([indent, ";"])

            if node_type == "empty_stmt":
                code = code + "; "

            if node_type == "do":
                code = code + "do "
                do_flag = True

            if node_type == "class":
                stack.append([indent, "class"])
                class_flag = True


            if node_type == "interface":
                stack.append([indent, "interface"])
                class_flag = True

            if node_type == "enum":
                code = code + "enum "

            if node_type == "super" and indent <= prev_indent and indent != 0:
                code = code + ", "

            if node_type == "annotation":
                code = code + "@"

            if node_type == "annotation_defn":
                code = code + "@interface"

            if node_type == "extends":
                code = code + "extends "

            if node_type == "implements":
                code = code + "implements "

            if node_type == "lambda":
                temp_i = iii+1
                temp_indent = indent+1
                while temp_i < len(lines):
                    temp_line = lines[temp_i]
                    temp_split_line = temp_line.split(":")
                    temp_node_type = ""
                    temp_indent = 0
                    for i, t in enumerate(temp_line):
                        if t != " ":
                            temp_indent = i
                            break
                    if indent == temp_indent:
                        break
                    if len(temp_split_line) > 1:
                        temp_node_type = temp_split_line[1][1:]
                    if temp_node_type == 'return':
                        return_lambda_flag = True
                        break
                    temp_i += 1
                lambda_flag = True

            if node_type == "finally":
                code = code + "finally "

            if node_type == "catch":
                code = code + "catch "

            if node_type == "try":
                code = code + "try "

            if node_type == "throw":
                code = code + "throw "

            if node_type == "throws":
                code = code + "throws "

            if node_type == "assert":
                code = code + "assert "

            if node_type == "synchronized":
                code = code + "synchronized "

            if node_type == "import":
                code = code + "import "
                stack.append([indent, ";"])

            if node_type == "package":
                code = code + "package "
                stack.append([indent, ";"])

            token = ""
            if len(split_line) > 2:
                colon_num = 0
                for i, t in enumerate(line):
                    if t == ":":
                        colon_num += 1
                    if colon_num == 2:
                        token = line[i + 2:]
                        break
            if token != "":
                code = code + token + " "
            prev_node_type = node_type
            prev_indent = indent

            if node_type == "specifier" and class_flag:
                code = code + stack[-1][1]+' '
                final_return = stack[-1][1]
                stack.pop()
                class_flag = False
        return code

    def __readAst(self, file_lines):
        i = 0
        while i < len(file_lines):

            if not file_lines[i] or not file_lines[i].strip():
                i += 1
                continue

            if file_lines[i][-1] == "\n":
                file_line = file_lines[i][:-1]
            else:
                file_line = file_lines[i]
            current_depth = 0
            indent = 0
            for c in file_line:
                if c == ' ':
                    indent += 1
                else:
                    break
            line_depth = indent // 4
            if line_depth == current_depth:
                node_info = file_line.split(' ')
                node_location = node_info[-1]
                start, end = eval(node_location)
                node_code = self.__code[start:end+1]
                self.__root_node = GumTreeAstNode(self, self.__new_idx, node_code)
                if len(node_info) >= 3:

                    self.__root_node.type = GumTreeAstType(node_info[0][:-1])
                    value = ""
                    for j in range(1, len(node_info) - 1):
                        value = value + node_info[j] + " "
                    value = value[:-1]
                    self.__root_node.location = node_info[-1]
                else:
                    self.__root_node.type = GumTreeAstType(node_info[0])
                    self.__root_node.location = node_info[1]
                self.__node_dict[self.__new_idx] = self.__root_node
                self.__node_dict_by_location[
                    self.__root_node.type.type_name + " " + self.__root_node.location] = self.__root_node
                parent_node_id = self.__new_idx
                self.__new_idx += 1
                i += 1
                continue


            if line_depth == current_depth + 1:
                stop_line = self.__readSubTree(parent_node_id, file_lines, i, current_depth + 1)
                i = stop_line
            i += 1

    def __readSubTree(self, parent_node_id, file_lines, cur_line, current_depth):
        i = cur_line
        while i < len(file_lines):

            if not file_lines[i] or not file_lines[i].strip():
                i += 1
                continue

            if file_lines[i][-1] == "\n":
                file_line = file_lines[i][:-1]
            else:
                file_line = file_lines[i]
            indent = 0
            for c in file_line:
                if c == ' ':
                    indent += 1
                else:
                    break
            line_depth = indent // 4
            if line_depth == current_depth:
                node_info = file_line[indent:].split(' ')
                node_location = node_info[-1]
                start, end = eval(node_location)
                node_code = self.__code[start:end+1]
                if len(node_info) >= 3:
                    type = GumTreeAstType(node_info[0][:-1])
                    value = ""
                    for j in range(1, len(node_info) - 1):
                        value = value + node_info[j] + " "
                    value = value[:-1]
                    location = node_info[-1]
                else:
                    type = GumTreeAstType(node_info[0])
                    value = ''
                    location = node_info[1]
                self.addSingleNode(type, value, parent_node_id, len(self.__node_dict[parent_node_id].children), location, node_code)
                cur_parent_node_id = self.__new_idx - 1
                i += 1
                continue
            if line_depth == current_depth + 1:
                stop_line = self.__readSubTree(cur_parent_node_id, file_lines, i, current_depth + 1)
                i = stop_line
            if line_depth < current_depth:
                return i - 1
            i += 1
        return i - 1
