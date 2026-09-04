import logging
import time
import pickle
from Hierarchical import clustering, run_cluster
logging.basicConfig(level=logging.ERROR, format='%(asctime)s %(message)s')


def pattern_clustering(step):
    if step == 0:
        working_set = []
        time_before = time.time()
        with open(pattern_path, 'rb') as f:
            a = pickle.load(f)
            for v in a.values():
                working_set.extend(v[1])
        time_after = time.time()
        print('read file time:', time_after-time_before)
        clustering(working_set)
    elif step == 1:
        run_cluster(llm=llm, resume=resume)


pattern_path='../datasets/ICVul/ICVul_10000.pkl'
llm = False
resume = False
pattern_clustering(1)
