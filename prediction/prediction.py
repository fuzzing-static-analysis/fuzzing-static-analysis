#!/usr/bin/python3

import pandas as pd

TIME = 82800

# First list of fuzzers that was in 0522 experiment
fuzzer_list_1 = [
    "libafl",
    "libafl_fuzzbench_cov_accounting",
    "libafl_fuzzbench_explore",
    "libafl_fuzzbench_mopt",
    "libafl_fuzzbench_value_profile",
    "libafl_fuzzbench_weighted",
    "libafl_fuzzbench_cmplog",
    "libafl_fuzzbench_naive",
    "libafl_fuzzbench_fast",
    "libafl_fuzzbench_rand_scheduler",
]
pd.set_option('display.max_rows', None)
pd.set_option('display.max_rows', None)


df0522 = pd.read_csv("./experiments/libafl0522.csv", engine='python')
selected0522 = df0522[df0522['fuzzer'].isin(fuzzer_list_1)]
selected0522 = selected0522[['fuzzer', 'benchmark', 'edges_covered', 'time']]
selected0522 = selected0522[selected0522['time'] == TIME]

benchmarks = selected0522.benchmark.unique()

# list of fuzzers in 0602 experiment
fuzzer_list_2 = [
    "libafl_fuzzbench_ngram4",
    "libafl_fuzzbench_ngram8",
    "libafl_fuzzbench_naive_ctx",
]

df0602 = pd.read_csv("./experiments/libafl0602.csv", engine='python')
selected0602 = df0602[df0602['fuzzer'].isin(fuzzer_list_2)]
selected0602 = selected0602[['fuzzer', 'benchmark', 'edges_covered', 'time']]
selected0602 = selected0602[selected0602['time'] == TIME]

# list of fuzzers in 0622 experiment for grimoire
fuzzer_list_3 = [
    "libafl_fuzzbench_grimoire",
]
df0622 = pd.read_csv("./experiments/libafl0622.csv", engine = 'python')
selected0622 = df0622[df0622['fuzzer'].isin(fuzzer_list_3)]
selected0622 = selected0622[['fuzzer', 'benchmark', 'edges_covered', 'time']]
selected0622 = selected0622[selected0622['time'] == TIME]


result = pd.concat([selected0522, selected0602, selected0622])
fuzzer_list = fuzzer_list_1 + fuzzer_list_2 + fuzzer_list_3

result.to_csv("result.csv")

import matplotlib.pyplot as plt

import json
import numpy as np


# Load the second batch of the experiment data
fuzzer_sbft_1 = [
    "libafl_fuzzbench_cmplog",
    "libafl_fuzzbench_cov_accounting",
    "libafl_fuzzbench_fast",
    "libafl_fuzzbench_explore",
    "libafl_fuzzbench_mopt",
]

fuzzer_sbft_2 = [
    "libafl_fuzzbench_naive",
    "libafl_fuzzbench_naive_ctx",
    "libafl_fuzzbench_ngram4",
    "libafl_fuzzbench_ngram8",
]

fuzzer_sbft_3 = [
    "libafl_fuzzbench_weighted",
    "libafl_fuzzbench_value_profile",
    "libafl_fuzzbench_rand_scheduler",
]

fuzzer_sbft_4 = [
    "libafl_fuzzbench_grimoire",    
]

fuzzer_sbft_5 = [
    "libafl_composition",
]

good_benchmark_sbft = [
    "arduinojson_json_fuzzer",
    "assimp_assimp_fuzzer",
    "astc-encoder_fuzz_astc_physical_to_symbolic",
    "brotli_decode_fuzzer",
    "double-conversion_string_to_double_fuzzer",
    "draco_draco_pc_decoder_fuzzer",
    "firestore_firestore_serializer_fuzzer",
    "fmt_chrono-duration-fuzzer",
    "guetzli_guetzli_fuzzer",
    "icu_unicode_string_codepage_create_fuzzer",
    "libaom_av1_dec_fuzzer",
    "libcoap_pdu_parse_fuzzer",
    "libhevc_hevc_dec_fuzzer",
]


df0903 = pd.read_csv("./experiments/libafl0903.csv", engine='python')
df0904 = pd.read_csv("./experiments/libafl0904.csv", engine='python')
df0905 = pd.read_csv("./experiments/libafl0905.csv", engine='python')
df0906 = pd.read_csv("./experiments/libafl0906.csv", engine='python')
df0919 = pd.read_csv("./experiments/libafl0920.csv", engine='python')
jemalloc1 = pd.read_csv("./experiments/jemalloc1.csv", engine='python')
jemalloc2 = pd.read_csv("./experiments/jemalloc2.csv", engine='python')
jemalloc3 = pd.read_csv("./experiments/jemalloc3.csv", engine='python')

compositionv2 = pd.read_csv("./experiments/compositionv2.csv", engine='python')

# first batch of data
selected0903 = df0903[df0903['fuzzer'].isin(fuzzer_sbft_1)]
selected0903 = selected0903[['fuzzer', 'benchmark', 'edges_covered', 'time']]
selected0903 = selected0903[selected0903['time'] == TIME]
# assimp is broken
selected0903 = selected0903[selected0903['benchmark'] != 'assimp_assimp_fuzzer']

# second batch of data
selected0904 = df0904[df0904['fuzzer'].isin(fuzzer_sbft_2)]
selected0904 = selected0904[['fuzzer', 'benchmark', 'edges_covered', 'time']]
selected0904 = selected0904[selected0904['time'] == TIME]
# assimp is broken
selected0904 = selected0904[selected0904['benchmark'] != 'assimp_assimp_fuzzer']

# third batch of data
selected0905 = df0905[df0905['fuzzer'].isin(fuzzer_sbft_3)]
selected0905 = selected0905[['fuzzer', 'benchmark', 'edges_covered', 'time']]
selected0905 = selected0905[selected0905['time'] == TIME]
# assimp is broken
selected0905 = selected0905[selected0905['benchmark'] != 'assimp_assimp_fuzzer']

# Why assimp was broken? we don't know, but it was some error due to internal malloc error in glibc malloc (andrea said so)
# The solution we took is to use jemalloc instead for the assimp experiment

result_sbft = pd.concat([selected0903, selected0904, selected0905])

# brotli was broken on naive-ctx
selected0906 = df0906[df0906['fuzzer'].isin(['libafl_fuzzbench_naive_ctx'])]
selected0906 = selected0906[selected0906['benchmark'] == 'brotli_decode_fuzzer']
selected0906 = selected0906[['fuzzer', 'benchmark', 'edges_covered', 'time']]
selected0906 = selected0906[selected0906['time'] == TIME]

# composition fuzzer
selected_composition = compositionv2[compositionv2['fuzzer'].isin(['libafl_fuzzbench_composition'])]
selected_composition = selected_composition[['fuzzer', 'benchmark', 'edges_covered', 'time']]
selected_composition = selected_composition[selected_composition['time'] == TIME]

# These jemallocs are, as said before, for assimp target
jemalloc1 = jemalloc1[['fuzzer', 'benchmark', 'edges_covered', 'time']]
jemalloc1 = jemalloc1[jemalloc1['time']==TIME]
# removing it cause it's using old result
jemalloc1 = jemalloc1[jemalloc1['fuzzer'] != 'libafl_fuzzbench_composition']
jemalloc2 = jemalloc2[['fuzzer', 'benchmark', 'edges_covered', 'time']]
jemalloc2 = jemalloc2[jemalloc2['time']==TIME]
jemalloc3 = jemalloc3[['fuzzer', 'benchmark', 'edges_covered', 'time']]
jemalloc3 = jemalloc3[jemalloc3['time']==TIME]

# Replace it with new data. this one supplements libafl_fuzzbench_naive_ctx data on brotli

result_sbft = pd.concat([result_sbft, selected0906, selected_composition])
result_sbft = pd.concat([result_sbft, jemalloc1, jemalloc2, jemalloc3])
result_sbft = result_sbft[result_sbft['benchmark'].isin(good_benchmark_sbft)]
result_sbft.to_csv('result_sbft.csv')

for good in good_benchmark_sbft:
    result_for_this_bench = result_sbft[(result_sbft['benchmark'] == good)]
    # print(good)
    md = result_for_this_bench.groupby('fuzzer')['edges_covered'].median()
    # print(md.sort_values(ascending=False))

import numpy
from numpy import std, mean, sqrt, nan
import statistics
import os

# same cohend calculation like the correlation part
def cohen_d(fuzzer, x, y):
    nx = len(x)
    ny = len(y)
    dof = nx + ny - 2
    divisor = sqrt(((nx-1)*std(x, ddof=1) ** 2 + (ny-1)*std(y, ddof=1) ** 2) / dof)
    d = (mean(x) - mean(y)) / divisor

    wa = nx+ny
    seki = nx * ny
    nijo = d * d
    v = sqrt((wa / seki) + (nijo / (2 * (wa - 2))))
    if numpy.isnan(v) or v == 0:
        print(fuzzer, nx, ny, dof)
        print(x, y)
    return (d, divisor, v)

def rank_key(d, target_key):
    sorted_items = sorted(d.items(), key=lambda x: x[1])
    
    # Finding the rank of the target_key
    for rank, (key, _) in enumerate(sorted_items, 1):
        if key == target_key:
            return rank
    print("rank_key error")
    return None  # Return None if the target_key is not found in the dictionary

# List up all the techniques we want to pick
# we don't use grimoire, as on some targets (assimp) it took too much time in the 
scheduler_league = ["libafl_fuzzbench_fast", "libafl_fuzzbench_explore", "libafl_fuzzbench_rand_scheduler", "libafl_fuzzbench_weighted", "libafl_fuzzbench_cov_accounting"]
feedback_league = ["libafl_fuzzbench_value_profile", "libafl_fuzzbench_naive_ctx", "libafl_fuzzbench_ngram4", "libafl_fuzzbench_ngram8"]
mutator_league = ["libafl_fuzzbench_cmplog", "libafl_fuzzbench_mopt"]


def get_league(fuzzer):
    global scheduler_league
    global feedback_league
    global mutator_league

    # just return the right global list
    # it's ugly but it works
    if fuzzer in scheduler_league:
        return scheduler_league
    elif fuzzer in feedback_league:
        return feedback_league
    elif fuzzer in mutator_league:
        return mutator_league
    elif fuzzer == "libafl_fuzzbench_naive":
        # for naive just return scheduler_league, or anything is fine
        # doens't really matter whatever it is. 
        # because we'll set its cohend to 0.0 later anyway
        return scheduler_league
    else:
        print("get_league error")

benchmarks = result['benchmark'].unique()

# this is the fuzzer to compare.
# pass it by env
FUZZER = os.environ['FUZZER']
cohend_rank_dict = dict()
for benchmark in benchmarks:

    competitors = get_league(FUZZER)
        
    all_cohen_d = dict()
    for competitor in competitors:
        # select the benchmark we want to compare
        benchmark_data = result[(result['benchmark'] == benchmark)]

        # libafl_naive is the baseline  
        baseline = benchmark_data[(benchmark_data['fuzzer'] == 'libafl_fuzzbench_naive')]
        # the target fuzzer
        target_fuzzer = benchmark_data[(benchmark_data['fuzzer'] == competitor)]

        s1 = []
        s2 = []
        for v in target_fuzzer['edges_covered']:
            s1.append(v)
        for v in baseline['edges_covered']:
            s2.append(v)
        if len(s1) != 0 and competitor != 'libafl_fuzzbench_naive':
            # compute cohen's d
            cohend, divisor, v = cohen_d(FUZZER, s1, s2)
            all_cohen_d[competitor] = cohend
        else:
            # set to -inf so we get it lowest rank later
            all_cohen_d[competitor] = float('-inf')

    # naive's cohen's d is 0.0. of course, by definition
    all_cohen_d['libafl_fuzzbench_naive'] = 0.0

    # let's see the median now
    value_list = [x for x in all_cohen_d.values() if x != float('-inf')]
    median = statistics.median(value_list)

    # for the ml thing to work, we need imputation, fill the missing value with median
    all_cohen_d = {k: median if v == float('-inf') else v for k, v in all_cohen_d.items()}
    
    rrrr = all_cohen_d[FUZZER]
    # this is the training dataset
    cohend_rank_dict[benchmark] = rrrr

# Now let's move on to the sbft dataset, basically it's the same thing
benchmarks_sbft = result_sbft['benchmark'].unique()
cohend_dict_rank_sbft = dict()
for benchmark in benchmarks_sbft:
    competitors = get_league(FUZZER)
    
    all_cohen_d = dict()
    for competitor in competitors:
        benchmark_data_sbft = result_sbft[(result_sbft['benchmark'] == benchmark)]
        baseline = benchmark_data_sbft[(benchmark_data_sbft['fuzzer'] == 'libafl_fuzzbench_naive')]
        target_fuzzer = benchmark_data_sbft[(benchmark_data_sbft['fuzzer'] == competitor)]
        s1 = []
        s2 = []
        for v in target_fuzzer['edges_covered']:
            s1.append(v)
        for v in baseline['edges_covered']:
            s2.append(v)
        if len(s1) != 0 and competitor != 'libafl_fuzzbench_naive':
            cohend, divisor, v = cohen_d(FUZZER, s1, s2)
            all_cohen_d[competitor] = cohend
        else:
            all_cohen_d[competitor] = float('-inf')
    all_cohen_d['libafl_fuzzbench_naive'] = 0.0
    rrrr = all_cohen_d[FUZZER]
    # This is the prediction dataset
    cohend_dict_rank_sbft[benchmark] = rrrr

import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
np.set_printoptions(precision=5, suppress=True, floatmode='fixed')

# Parse the data this is the same as the correlation part.
def run_analysis(file, property_data, filename, remove_outliers = False, sbft = False):
    feature_data = dict(sorted(property_data.items()))
    keys = feature_data.keys()

    values = {k: x[1] for k, x in feature_data.items()}
    q75, q25 = np.percentile(list(values.values()), [75 ,25])
    x_iqr = q75 - q25
    x_min = q25 - x_iqr * 1.5
    x_max = q75 + x_iqr * 1.5
    for k, v in values.items():
        # remove stuff outside the IQR range.
        # this is only for the training set
        if remove_outliers:
            if v < x_min or v > x_max:
                # set to nan, then we fill it later
                values[k] = np.NAN
    # if it is sbft (prediction) data set don't remove anything just return the dict
    if sbft:
        values = {k: v for k, v in values.items() if k in good_benchmark_sbft}
    return values

import os
file_list = []
file_list_sbft = []

# Retrieve the analysis files
for r, subdir, files in os.walk("../data"):
    for file in files:
        ab = os.path.join(r, file)
        file_list.append((ab, file))

for r, subdir, files in os.walk("../data_sbft"):
    for file in files:
        ab = os.path.join(r, file)
        file_list_sbft.append((ab, file))

# This is the generated files discribing which features are correlated with which feature
# You generate this from Cohen.ipynb
f = open("cohen_features.json")
cohen_features = json.load(f)

fuzzers_friend = get_league(FUZZER)
assert(competitors != None)

# now select the features that are at least relevant to one of the fuzzers in fuzzer league
good_features = set()
for fuzzer in fuzzers_friend:
    good_features |= set(cohen_features[fuzzer])

# print(good_features)
    

# Load the static analysis data for the training data set.
matrix = dict()
file_list.sort()
for ab, file in file_list:
    with open(ab) as f:
        property_data = json.load(f)
    assert(len(property_data) == 23)
    feature_filename = ab.lstrip("../data/")
    if feature_filename in good_features:
        matrix[feature_filename] = run_analysis(ab, property_data, file)


# Load the static analysis data for the prediction data set.
matrix_sbft = dict()
file_list_sbft.sort()
for ab, file in file_list_sbft:
    with open(ab) as f:
        property_data_sbft = json.load(f)
    assert(len(property_data_sbft) == 13)
    # Out of 17 fuzzers, 2 didn't build for libafl, 2 was not compatible with LTO
    feature_filename = ab.lstrip("../data_sbft/")
    if feature_filename in good_features:
        matrix_sbft[feature_filename] = run_analysis(ab, property_data_sbft, file, sbft = True)

# print(df)
df = pd.DataFrame.from_dict(matrix, orient='index')
df = df.transpose()

df['cohend'] = cohend_rank_dict
df_sbft = pd.DataFrame.from_dict(matrix_sbft, orient='index')
df_sbft = df_sbft.transpose()
df_sbft['cohend'] = cohend_dict_rank_sbft

# print(df)
# plt.figure(figsize=(310, 310))
corr_df = df.corr()
# sns.heatmap(corr_df, annot=True, cmap='coolwarm', cbar=True, square=True, linewidths=0.5)
# plt.title('Correlation Matrix Heatmap')
# plt.savefig('corr.png')
df.to_csv('prediction.csv')
df_sbft.to_csv('prediction_sbft.csv')
import statsmodels.api as sm
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import r2_score

# impute with median
df = df.apply(lambda col: col.fillna(col.median()))
# again, impute with median
df_sbft = df_sbft.apply(lambda col: col.fillna(col.median()))

X_train_all = df.drop(columns = ["cohend"])
y_train = df["cohend"]

# The correct one
X_predicted_all = df_sbft.drop(columns = ["cohend"])

rf_all = RandomForestRegressor(random_state = 0, n_estimators = 100)
rf_all.fit(X_train_all, y_train)

predictions_all = rf_all.predict(X_predicted_all)
# r2_all = r2_score(df_sbft["cohend"], predictions_all)
print("prediction", predictions_all.tolist())
print("actual", df_sbft["cohend"].to_list())
