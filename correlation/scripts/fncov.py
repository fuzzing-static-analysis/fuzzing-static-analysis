#!/usr/bin/env python
# coding: utf-8
# Spearman.py 同様, jupyternotbook使えないから作っただけ
# In[29]:


#!/usr/bin/env python
# coding: utf-8

# In[25]:


import pandas as pd

TIME = 82800

fuzzer_all = [
    "libafl_fuzzbench_cov_accounting",
    "libafl_fuzzbench_explore",
    "libafl_fuzzbench_mopt",
    "libafl_fuzzbench_value_profile",
    "libafl_fuzzbench_weighted",
    "libafl_fuzzbench_cmplog",
    "libafl_fuzzbench_naive",
    "libafl_fuzzbench_fast",
    "libafl_fuzzbench_rand_scheduler",
    "libafl_fuzzbench_ngram4",
    "libafl_fuzzbench_ngram8",
    "libafl_fuzzbench_naive_ctx",
    "libafl_fuzzbench_grimoire",
]
pd.set_option('display.max_rows', None)
pd.set_option('display.max_rows', None)


df = pd.read_json("./experiments/alternative-coverage.json")
import matplotlib.pyplot as plt

import json
import numpy as np
benchmarks = [x for x in df.index]


# In[30]:


# Spearman
# In[ ]:
import warnings
warnings.filterwarnings("ignore")
# mode = "PERCENTILE"
pd.options.mode.chained_assignment = None 

corr_result = dict()
def get_cmap(n, name='hsv'):
    '''Returns a function that maps each index in 0, 1, ..., n-1 to a distinct 
    RGB color; the keyword argument name must be a standard mpl colormap name.'''
    return plt.cm.get_cmap(name, n)
def run_analysis(file, property_data, filename):
    print("---------------------------------------------------------------")
    res_spearman = dict()
    res_cohen = dict()
    print(ab)
    
    for FUZZER in fuzzer_all:
        points = dict()
        for benchmark in benchmarks:
            for fuzzer in fuzzer_list:
                if fuzzer == FUZZER:
                    data = result[(result['benchmark'] == benchmark)]
                    property_rank, property_value = property_data[benchmark]
    
                    data.loc[:, 'fuzzer_rank'] = data.loc[:, 'edges_covered'].rank(method = 'average')
                    data = data[(data['fuzzer'] == fuzzer)]

                    for fuzzer_rank in data['fuzzer_rank']:
                        if benchmark in points:
                            points[benchmark].append((fuzzer_rank, property_rank))
                        else:
                            points[benchmark] = [(fuzzer_rank, property_rank)]
        # ss = [(fuzzer_rank, property_rank, property_value) for property_rank, (fuzzer_rank, property_value) in enumerate(sorted(points, key = lambda item: item[1]))]

        
        # ss.sort(key = lambda item: item[1])
        X = []
        y = []
        cmap = get_cmap(len(points.keys()))
        for (i, (benchmark, vec)) in enumerate(points.items()):
            colored_X = []
            colored_y = []
            for fuzzer_rank, property_rank in vec:
                X.append(property_rank)
                y.append(fuzzer_rank)
                colored_X.append(property_rank)
                colored_y.append(fuzzer_rank)
            
            plt.scatter(colored_X, colored_y, c = cmap(i), label = benchmark)

        reg = np.polyfit(X, y, 1)
        f = np.poly1d(reg)
    
        # plt.scatter(X, y)
        # plt.xlabel("property rank")
        # plt.ylabel("fuzzer rank")
        # plt.title("{} {}".format(filename, FUZZER))
        # plt.legend(bbox_to_anchor=(1.04, 1), loc="upper left")
        # plt.plot(X, f(X), color = "r")
        # print(f)
        from scipy import stats
        import math
        # print(stats.spearmanr(X, y))
        spe = stats.spearmanr(X, y)
        tau = stats.kendalltau(X, y).statistic
        spearman_r = spe.statistic
        pvalue = spe.pvalue
        count = len(X)
        stderr = 1.0 / math.sqrt(count - 3)
        delta = 1.96 * stderr
        lower = math.tanh(math.atanh(spearman_r) - delta)
        upper = math.tanh(math.atanh(spearman_r) + delta)
        res_spearman[FUZZER] = (spearman_r, tau, pvalue)
        plt.annotate(text='r = {}, p = {}'.format(spearman_r, pvalue), xy=(0.03, 0.03), xycoords='figure fraction')
        
        # print("Saved picture for", FUZZER)
        # print(X)
        # print(y)
        # plt.show()
        plt.clf()
    
    print("Correlation: ")
    for (key, (r, tau, pvalue)) in res_spearman.items():
        # if (r >= 0.40 or r <= -0.40) and pvalue <= 0.05:
        #     pass
        if key in corr_result:
            corr_result[key].append((file, (r, tau, pvalue)))
        else:
            corr_result[key] = [(file, (r, tau, pvalue))]
    '''
    print("No correlation: ")
    for key, r in res_spearman.items():
        if r.statistic < 0.30 and r.statistic > -0.30:
            print(key, r.statistic)
    print()
    '''
import os
file_list = []
for r, subdir, files in os.walk("../data"):
    for file in files:
        ab = os.path.join(r, file)
        file_list.append((ab, file))

file_list.sort()
for ab, file in file_list:
    property_data = dict()
    with open(ab) as f:
        property_data = json.load(f)
    print(len(property_data))
    assert(len(property_data) == 23)
    run_analysis(ab, property_data, file)
# In[ ]:
for k, v in corr_result.items():
    v.sort(key = lambda x: x[1][0])
    for nnn, (r, tau, _pvalue) in v:
        print(k, nnn, r, tau)


# In[ ]:




