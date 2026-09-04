import pandas as pd
import numpy as np


class CWEProcessor():
    def __init__(self):
        cwe_info = pd.read_csv("../utils/assets/cwe_info_1000.csv")
        self.cwe_graph = None
        self.cwe_dict_tree = {}
        self.cwe_dict_tree = {}
        cwe_info['cwe_unique'] = "CWE-"+cwe_info['id'].astype(str)
        cwe_info['cwe_str'] = cwe_info['cwe_unique']
        self.cwe_graph = self.generate_graph(cwe_info, cwe_info)

        for node_obj in self.cwe_graph[0]['children']:
            top_lvl_parent = node_obj['id']
            self.traverse_tree(node_obj, self.cwe_dict_tree, top_lvl_parent)
            self.cwe_dict_tree[node_obj['id']] = node_obj['id']

    def generate_graph(self, cve_df_split, cwe_info):
        total = cve_df_split[cve_df_split['cwe_unique'].isin(cwe_info['cwe_str'].unique())].shape[0]

        data = [
            {
                'id': 'All',
                'datum': total,
                'children' : [],

            }
        ]


        for row in cwe_info[cwe_info.parent_name.isna()].itertuples():
            pillar_name = row.name
            pillar_id = row.id
            pillar_cwe_str = row.cwe_str


            children = []
            size = []


            children_rows = cwe_info[cwe_info.parent_id == pillar_id]
            if children_rows.shape[0] > 0:
                for child_row in children_rows.itertuples():
                    child_data = self.generate_graph_helper(child_row, cwe_info, cve_df_split)
                    if child_data["datum"] > 0:
                        children.append(child_data)
                        size.append(child_data["datum"])

            datum = cve_df_split[cve_df_split.cwe_unique == pillar_cwe_str].shape[0] + np.sum(size)


            if len(children) > 0:
                instance_data = {
                    "id": pillar_cwe_str,
                    "datum": datum,
                    "children": children,
                    "cwe_str": pillar_cwe_str,

                }
            else:
                instance_data = {
                    "id": pillar_cwe_str,
                    "datum": datum,
                    "cwe_str": pillar_cwe_str,

                }
            data[0]["children"].append(instance_data)
        return data

    def generate_graph_helper(self, row: pd.core.series.Series, cwe_info: pd.DataFrame, cve_df_split: pd.DataFrame):
        instance_name = row.name
        instance_id = row.id
        instance_cwe_str = row.cwe_str

        children = []
        size = []


        children_rows = cwe_info[cwe_info.parent_id == instance_id]
        if children_rows.shape[0] > 0:
            for child_row in children_rows.itertuples():
                child_data = self.generate_graph_helper(child_row, cwe_info, cve_df_split)
                if child_data["datum"] > 0:
                    children.append(child_data)
                    size.append(child_data["datum"])

        datum = cve_df_split[cve_df_split.cwe_unique == instance_cwe_str].shape[0] + np.sum(size)

        if len(children) > 0:
            instance_data = {
                "id": instance_cwe_str,
                "datum": datum,
                "children": children,
                "cwe_str": instance_cwe_str,

            }
        else:
            instance_data = {
                "id": instance_cwe_str,
                "datum": datum,
                "cwe_str": instance_cwe_str,

            }

        return instance_data

    def traverse_tree(self, node, child_parent, top_lvl_parent):
        if node['id'] not in child_parent:
            child_parent[node['id']] = "<>".join(top_lvl_parent.split("<>")[1:])
        if 'children' in node and len(node['children']) > 0:
            for child in node['children']:
                self.traverse_tree(child, child_parent, top_lvl_parent+"<>"+node["id"])

    def process_cwe(self, cwe: str) -> tuple:
        try:
            ancestry = self.cwe_dict_tree[cwe]
            if cwe not in ancestry:
                ancestry += "<>"+cwe
            return ancestry, ancestry.split("<>")[0]
        except:
            return cwe, cwe

    def get_father(self,cwe_id):
        if cwe_id is None:
            return None
        ancestor_tree,ancestor = self.process_cwe(cwe_id)
        ancestor_list = ancestor_tree.split('<>')
        if len(ancestor_list) == 1:
            return cwe_id
        else:
            return ancestor_list[-2]
    def replace_son_to_father(self,cwe_dict,df):
        for cwe, count in cwe_dict:
            father = self.get_father(cwe)

            if father !=cwe and count < 100:
                df.loc[df['CWE process'] == cwe, 'CWE process'] = father
                cwe_dict = df['CWE process'].value_counts().to_dict()
                cwe_dict = sorted(cwe_dict.items(), key=lambda x: x[1])
                self.replace_son_to_father(cwe_dict,df)
        return df
