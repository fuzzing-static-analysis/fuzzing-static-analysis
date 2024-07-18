#!/usr/bin/python3

# Parse the result and make a beautiful latex table!

import subprocess
import os
import math
fuzzer = [
    "libafl_fuzzbench_cov_accounting",
    "libafl_fuzzbench_explore",
    "libafl_fuzzbench_mopt",
    "libafl_fuzzbench_value_profile",
    "libafl_fuzzbench_weighted",
    "libafl_fuzzbench_cmplog",
    "libafl_fuzzbench_fast",
    "libafl_fuzzbench_rand_scheduler",
    "libafl_fuzzbench_ngram4",
    "libafl_fuzzbench_ngram8",
    "libafl_fuzzbench_naive_ctx",
]


scheduler_league = ["libafl_fuzzbench_fast", "libafl_fuzzbench_explore", "libafl_fuzzbench_rand_scheduler", "libafl_fuzzbench_weighted", "libafl_fuzzbench_cov_accounting"]
feedback_league = ["libafl_fuzzbench_value_profile", "libafl_fuzzbench_naive_ctx", "libafl_fuzzbench_ngram4", "libafl_fuzzbench_ngram8"]
mutator_league = ["libafl_fuzzbench_cmplog", "libafl_fuzzbench_mopt"]

# parsing the python3 list
def parse(f, text):
    print("parsing", f)
    text = text.split('\n')
    for line in text:
        if line.startswith("prediction"):
            line = line.split('[')[1]
            line = line.split(']')[0]
            line = line.split()
            line = [float(x.rstrip(',')) for x in line]
            pre = line
        elif line.startswith("actual"):
            line = line.split('[')[1]
            line = line.split(']')[0]
            line = line.split(' ')
            line = [float(x.rstrip(',')) for x in line]
            act = line

    return pre, act

res = dict()
for f in fuzzer:
    os.environ['FUZZER'] = f 
    ret = subprocess.run(['./prediction.py'], capture_output=True, text=True)
    pre, act = parse(f, ret.stdout)
    res[f] = dict()
    res[f]['pre'] = pre
    res[f]['act'] = act

def find_effect_size_diff(tuple_list, fuzzer):
    for i, (name, value) in enumerate(tuple_list):
        if name == fuzzer:
            return value - tuple_list[0][1]

def rank(tuple_list, fuzzer):
    for i, (name, value) in enumerate(tuple_list):
        if name == fuzzer:
            return i
        

# print(res)
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

text = ""
s_list = []
for i in range(13):
    s = 0
    s2 = 0
    mutators_pre = []
    mutators_act = []
    feedbacks_pre = []
    feedbacks_act = []
    schedulers_pre = []
    schedulers_act = []

    # Add all the data
    for mutator in mutator_league:
        mutators_pre.append((mutator, res[mutator]['pre'][i]))
        mutators_act.append((mutator, res[mutator]['act'][i]))
    mutators_pre.append(('libafl_fuzzbench_naive', 0))
    mutators_act.append(('libafl_fuzzbench_naive', 0))

    for feedback in feedback_league:
        feedbacks_pre.append((feedback, res[feedback]['pre'][i]))
        feedbacks_act.append((feedback, res[feedback]['act'][i]))
    feedbacks_pre.append(('libafl_fuzzbench_naive', 0))
    feedbacks_act.append(('libafl_fuzzbench_naive', 0))


    for scheduler in scheduler_league:
        schedulers_pre.append((scheduler, res[scheduler]['pre'][i]))
        schedulers_act.append((scheduler, res[scheduler]['act'][i]))
    schedulers_pre.append(('libafl_fuzzbench_naive', 0))
    schedulers_act.append(('libafl_fuzzbench_naive', 0))

    # Sort it, the best one comes at 0th position!
    mutators_pre.sort(key = lambda x: x[1], reverse = True)
    mutators_act.sort(key = lambda x: x[1], reverse = True)
    feedbacks_pre.sort(key = lambda x: x[1], reverse = True)
    feedbacks_act.sort(key = lambda x: x[1], reverse = True)
    schedulers_pre.sort(key = lambda x: x[1], reverse = True)
    schedulers_act.sort(key = lambda x: x[1], reverse = True)

    print(good_benchmark_sbft[i])
    # print(mutators_pre)
    # print(mutators_act)

    # check the rank of the prediction
    diff = rank(mutators_act, mutators_pre[0][0])
    # check effect size too.
    effect_size_diff = abs(find_effect_size_diff(mutators_act, mutators_pre[0][0]))
    if effect_size_diff < 0.5:
        print(mutators_pre, effect_size_diff)
    s += diff
    
    # print(feedbacks_pre)
    # print(feedbacks_act)
    # repeat for the others
    diff = rank(feedbacks_act, feedbacks_pre[0][0])
    effect_size_diff = abs(find_effect_size_diff(feedbacks_act, feedbacks_pre[0][0]))
    if effect_size_diff < 0.5:
        print(feedbacks_pre, effect_size_diff)
    s += diff

    # print(schedulers_pre)
    # print(schedulers_act)
    # repeat for the others
    diff = rank(schedulers_act, schedulers_pre[0][0])
    effect_size_diff = abs(find_effect_size_diff(schedulers_act, schedulers_pre[0][0]))
    if effect_size_diff < 0.5:
        print(schedulers_pre, effect_size_diff)
    s += diff
    s_list.append(s)
    # print a latex table
    benchmark_name = good_benchmark_sbft[i].replace("_", "\\_").replace("-", "{{\\text -}}")
    predicted_best_scheduler = schedulers_pre[0][0].replace("_", "\\_").replace("libafl\\_fuzzbench\\_", "")
    predicted_best_scheduler_rank = rank(schedulers_act, schedulers_pre[0][0]) + 1
    actual_best_scheduler = schedulers_act[0][0].replace("_", "\\_").replace("libafl\\_fuzzbench\\_", "")
    text += f"${benchmark_name}$ & schedulers & {predicted_best_scheduler} & $ {predicted_best_scheduler_rank} / 6$ & ${actual_best_scheduler}$ \\\\\n\\hline\n"

    benchmark_name = good_benchmark_sbft[i].replace("_", "\\_").replace("-", "{{\\text -}}")
    predicted_best_feedback = feedbacks_pre[0][0].replace("_", "\\_").replace("libafl\\_fuzzbench\\_", "")
    predicted_best_feedback_rank = rank(feedbacks_act, feedbacks_pre[0][0]) + 1
    actual_best_feedback = feedbacks_act[0][0].replace("_", "\\_").replace("libafl\\_fuzzbench\\_", "")
    text += f"${benchmark_name}$ & feedbacks & {predicted_best_feedback} & $ {predicted_best_feedback_rank} / 5 $ & ${actual_best_feedback}$ \\\\\n\\hline\n"

    benchmark_name = good_benchmark_sbft[i].replace("_", "\\_").replace("-", "{{\\text -}}")
    predicted_best_mutator = mutators_pre[0][0].replace("_", "\\_").replace("libafl\\_fuzzbench\\_", "")
    predicted_best_mutator_rank = rank(mutators_act, mutators_pre[0][0]) + 1
    actual_best_mutator = mutators_act[0][0].replace("_", "\\_").replace("libafl\\_fuzzbench\\_", "")
    text += f"${benchmark_name}$ & mutators & {predicted_best_mutator} & $ {predicted_best_mutator_rank} / 3$ & ${actual_best_mutator}$ \\\\\n\\hline\n"

print(s_list[1:6] + s_list[7:], sum(s_list[1:6] + s_list[7:]))

print(text)
# [1, 1, 7, 3, 0, 5, 4, 6, 1, 6, 3] 37
# [1, 4, 7, 4, 1, 4, 4, 9, 1, 2, 3] 40
