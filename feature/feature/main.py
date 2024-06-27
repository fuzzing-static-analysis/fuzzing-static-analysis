import os
import json
import util
from subprocess import check_output

fuzzer_list = [
    "bloaty_fuzz_target/out/fuzz_target",
    "curl_curl_fuzzer_http/out/curl_fuzzer_http",
    "freetype2_ftfuzzer/out/ftfuzzer",
    "harfbuzz_hb-shape-fuzzer/out/hb-shape-fuzzer",
    "jsoncpp_jsoncpp_fuzzer/out/jsoncpp_fuzzer",
    "lcms_cms_transform_fuzzer/out/cms_transform_fuzzer",
    "libjpeg-turbo_libjpeg_turbo_fuzzer/out/libjpeg_turbo_fuzzer",
    "libpcap_fuzz_both/out/fuzz_both",
    "libpng_libpng_read_fuzzer/out/libpng_read_fuzzer",
    "libxml2_xml/out/xml",
    "libxslt_xpath/out/xpath",
    "mbedtls_fuzz_dtlsclient/out/fuzz_dtlsclient",
    "openh264_decoder_fuzzer/out/decoder_fuzzer",
    "openssl_x509/out/x509",
    "openthread_ot-ip6-send-fuzzer/out/ot-ip6-send-fuzzer",
    "proj4_proj_crs_to_crs_fuzzer/out/proj_crs_to_crs_fuzzer",
    "re2_fuzzer/out/fuzzer",
    "sqlite3_ossfuzz/out/ossfuzz",
    "stb_stbi_read_fuzzer/out/stbi_read_fuzzer",
    "systemd_fuzz-link-parser/out/fuzz-link-parser",
    "vorbis_decode_fuzzer/out/decode_fuzzer",
    "woff2_convert_woff2ttf_fuzzer/out/convert_woff2ttf_fuzzer",
    "zlib_zlib_uncompress_fuzzer/out/zlib_uncompress_fuzzer",
]

I8_CMPs_ord = dict()
I16_CMPs_ord = dict()
I32_CMPs_ord = dict()
I64_CMPs_ord = dict()
# I128_CMPs_ord = dict()
I32_I64_CMPs_ord = dict()
I32_I64_I128_CMPs_ord = dict()
FLOAT_CMPs_ord = dict()
DOUBLE_CMPs_ord = dict()
POINTER_CMPs_ord = dict()
# STRUCT_CMPs_ord = dict()
# ARRAY_CMPs_ord = dict()
VECTOR_CMPs_ord = dict()
ARRAY_VECTOR_CMPs_ord = dict()

I8_ARG_ord = dict()
I16_ARG_ord = dict()
I32_ARG_ord = dict()
I64_ARG_ord = dict()
# I128_ARG_ord = dict()
I32_I64_ARG_ord = dict()
I32_I64_I128_ARG_ord = dict()
FLOAT_ARG_ord = dict()
DOUBLE_ARG_ord = dict()
POINTER_ARG_ord = dict()
# STRUCT_ARG_ord = dict()
# ARRAY_ARG_ord = dict()
# VECTOR_ARG_ord = dict()
ARRAY_VECTOR_ARG_ord = dict()

I8_ST_ord = dict()
I16_ST_ord = dict()
I32_ST_ord = dict()
I64_ST_ord = dict()
I128_ST_ord = dict()
I32_I64_ST_ord = dict()
I32_I64_I128_ST_ord = dict()
FLOAT_ST_ord = dict()
DOUBLE_ST_ord = dict()
POINTER_ST_ord = dict()
# STRUCT_ST_ord = dict()
# ARRAY_ST_ord = dict()
VECTOR_ST_ord = dict()
ARRAY_VECTOR_ST_ord = dict()

I8_AL_ord = dict()
I16_AL_ord = dict()
I32_AL_ord = dict()
I64_AL_ord = dict()
# I128_AL_ord = dict()
I32_I64_AL_ord = dict()
I32_I64_I128_AL_ord = dict()
FLOAT_AL_ord = dict()
DOUBLE_AL_ord = dict()
POINTER_AL_ord = dict()
STRUCT_AL_ord = dict()
ARRAY_AL_ord = dict()
VECTOR_AL_ord = dict()
ARRAY_VECTOR_AL_ord = dict()

SIZE_ord = dict()
BBs_ord = dict()

CMPs_ord = dict()
LOADs_ord = dict()
STOREs_ord = dict()
ALLOCAs_ord = dict()
BRANCHs_ord = dict()
CALLs_ord = dict()
BINARYOPs_ord = dict()

STR_CMPs_ord = dict()
MEM_CMPs_ord = dict()
STR_MEM_CMPs_ord = dict()
INT_CMPs_ord = dict()
FLOATs_CMPs_ord = dict()

I64_CMPs_ord = dict()

m_AP_ord = dict()
h_AP_ord = dict()

CYCLOMATIC_ord = dict()
ABC_ord = dict()

NE_LV_MEAN_ord = dict()

AVG_MIN_PATH_CFGs = dict()
MIN_PATH_CFGs = dict()
CYCLE_CFGs = dict()

NODE_DDGs = dict()
EDGE_DDGs = dict()

CM_GL_ord = dict()
CM_NZ_ord = dict()

TEST_ORD = dict()
# TABLEs = dict()

def dump_stats(jss):
    for key, v in jss.items():
        print(key, v)


def filename(filename):
    fn = filename.split('/')[-1].replace('#', '/')
    return fn


def demangle(name):
    demangled = str(check_output(["c++filt", "-p", name]), encoding='utf-8')
    return demangled


def json_read(fuzzer, ana, ddg, table):
    fuzzer_dir = "/".join(fuzzer.split("/")[:2])
    lto_safe_func_list_file = os.path.join(
        os.path.join(
            "../../coverage_binary/result_lto",
            fuzzer_dir),
        "func.txt")
    lto_safe_func_list = []
    # Open the func list from the lto-ed executable
    with open(lto_safe_func_list_file) as funcs:
        for line in funcs.readlines():
            lto_safe_func_list.append(line.removesuffix('\n'))

    json_data = dict()
    lks_data = dict()
    cfg_data = dict()
    # Gather func list from source
    for (json_file, lks_file, cfg_file) in ana:
        with open(json_file) as js:
            # source_file_name = filename(file)

            jss = json.load(js)

            if jss is not None:
                json_data = json_data | jss
            # print("FILE", file, "Before", before, "After", after, "DUP", dup)

        with open(lks_file) as lks:
            lkss = json.load(lks)
            lkss_unpacked = dict()
            # Unpack

            if lkss is not None:
                for modulename, content in lkss.items():
                    for struct_name, data in content.items():
                        lkss_unpacked[struct_name] = data

                lks_data = lks_data | lkss_unpacked

        with open(cfg_file) as cfg:
            cfgg = json.load(cfg)
            parsed_graph = util.parse_cfg(cfgg)
            if parsed_graph is not None:
                cfg_data = cfg_data | parsed_graph


    ddg_data = dict()
    # Do the same for ddg, table as ana
    for ddg_file in ddg:
        with open(ddg_file) as ddgj:
            lines = ddgj.readlines()
            ddg_graph = []
            for i in range(0, len(lines), 2):
                source = lines[i].rstrip()
                sink = lines[i + 1].strip()
                ddg_graph.append((source, sink))

            parsed_graph = util.parse_ddg(ddg_graph)
            if parsed_graph is not None:
                ddg_data = ddg_data | parsed_graph


    table_data = dict()
    for table_file in table:
        with open(table_file) as tablej:
            tablejs = json.load(tablej)
            if tablejs is not None:
                table_data = table_data | tablejs


    # print(r, json_data.keys())
    # print(internal_funcs[fuzzer])

    # get_extcalls(fuzzer, json_data)

    # before = len(json_data.keys())

    # LTO
    for fn_name in list(json_data.keys()):
        if fn_name not in lto_safe_func_list:
            json_data.pop(fn_name)

    # after = len(json_data.keys())
    print(fuzzer_dir, len(json_data.keys()), "functions")

    # json_data is the "main" data, pass it to everything, because it knows which functions are omitted after LTO

    util.get_graph_features(fuzzer, "avgminpath", AVG_MIN_PATH_CFGs, json_data, cfg_data)
    util.get_graph_features(fuzzer, "minpath", MIN_PATH_CFGs, json_data, cfg_data)
    util.get_graph_features(fuzzer, "cycle", CYCLE_CFGs, json_data, cfg_data)
    util.get_graph_features(fuzzer, "node", NODE_DDGs, json_data, ddg_data)
    util.get_graph_features(fuzzer, "edge", EDGE_DDGs, json_data, ddg_data)

    # util.test_aaa(TEST_ORD, fuzzer, json_data, lks_data)

    # util.get_struct_freq_stats_per_wr_inst(0, INT_FREQ_per_WR_INST_ord, fuzzer, json_data, lks_data)
    # util.get_struct_freq_stats_per_wr_inst(1, PTR_FREQ_per_WR_INST_ord, fuzzer, json_data, lks_data)
    # util.get_struct_freq_stats_per_wr_inst(2, STRUCT_FREQ_per_WR_INST_ord, fuzzer, json_data, lks_data)
    # util.get_struct_freq_stats_per_wr_inst(3, ARRAY_FREQ_per_WR_INST_ord, fuzzer, json_data, lks_data)
    # util.get_struct_freq_stats_per_wr_inst(4, DOUBLE_FREQ_per_WR_INST_ord, fuzzer, json_data, lks_data)
    # util.get_struct_freq_stats_per_wr_inst(5, FLOAT_FREQ_per_WR_INST_ord, fuzzer, json_data, lks_data)
    # util.get_struct_freq_stats_per_wr_inst(6, TOTAL_SIZE_per_WR_INST_ord, fuzzer, json_data, lks_data)
    # util.get_struct_double_float_freq_stats_per_wr_inst(DOUBLE_FLOAT_FREQ_per_WR_INST_ord, fuzzer, json_data, lks_data)
# 
    # util.get_struct_freq_stats_per_bb(0, INT_FREQ_per_BB, fuzzer, json_data, lks_data)
    # util.get_struct_freq_stats_per_bb(1, PTR_FREQ_per_BB, fuzzer, json_data, lks_data)
    # util.get_struct_freq_stats_per_bb(2, STRUCT_FREQ_per_BB, fuzzer, json_data, lks_data)
    # util.get_struct_freq_stats_per_bb(3, ARRAY_FREQ_per_BB, fuzzer, json_data, lks_data)
    # util.get_struct_freq_stats_per_bb(4, DOUBLE_FREQ_per_BB, fuzzer, json_data, lks_data)
    # util.get_struct_freq_stats_per_bb(5, FLOAT_FREQ_per_BB, fuzzer, json_data, lks_data)
    # util.get_struct_freq_stats_per_bb(6, TOTAL_SIZE_per_BB, fuzzer, json_data, lks_data)
    # util.get_struct_double_float_freq_stats_per_wr_inst(DOUBLE_FLOAT_FREQ_per_BB, fuzzer, json_data, lks_data)

    util.get_APs("m AP", m_AP_ord, fuzzer, json_data, lks_data)
    util.get_APs("h AP", h_AP_ord, fuzzer, json_data, lks_data)

    util.get_type_in_insts({"i8"}, "cm ty", I8_CMPs_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"i16"}, "cm ty", I16_CMPs_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"i32"}, "cm ty", I32_CMPs_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"i64"}, "cm ty", I64_CMPs_ord, fuzzer, json_data, lks_data)
    # util.get_type_in_insts({"i128"}, "cm ty", I128_CMPs_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"i32", "i64"}, "cm ty", I32_I64_CMPs_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"i32", "i64", "i128"}, "cm ty", I32_I64_I128_CMPs_ord, fuzzer, json_data, lks_data)
    # util.get_type_in_insts({"float"}, "cm ty", FLOAT_CMPs_ord, fuzzer, json_data, lks_data)
    # util.get_type_in_insts({"double"}, "cm ty", DOUBLE_CMPs_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"pointer"}, "cm ty", POINTER_CMPs_ord, fuzzer, json_data, lks_data)
    # util.get_type_in_insts({"struct"}, "cm ty", STRUCT_CMPs_ord, fuzzer, json_data, lks_data)
    # util.get_type_in_insts({"array"}, "cm ty", ARRAY_CMPs_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"vector"}, "cm ty", VECTOR_CMPs_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"vector", "array"}, "cm ty", ARRAY_VECTOR_CMPs_ord, fuzzer, json_data, lks_data)

    util.get_type_in_insts({"i8"}, "ar ty", I8_ARG_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"i16"}, "ar ty", I16_ARG_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"i32"}, "ar ty", I32_ARG_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"i64"}, "ar ty", I64_ARG_ord, fuzzer, json_data, lks_data)
    # util.get_type_in_insts({"i128"}, "ar ty", I128_ARG_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"i32", "i64"}, "ar ty", I32_I64_ARG_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"i32", "i64", "i128"}, "ar ty", I32_I64_I128_ARG_ord, fuzzer, json_data, lks_data)
    # util.get_type_in_insts({"float"}, "ar ty", FLOAT_ARG_ord, fuzzer, json_data, lks_data)
    # util.get_type_in_insts({"double"}, "ar ty", DOUBLE_ARG_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"pointer"}, "ar ty", POINTER_ARG_ord, fuzzer, json_data, lks_data)
    # util.get_type_in_insts({"struct"}, "ar ty", STRUCT_ARG_ord, fuzzer, json_data, lks_data)
    # util.get_type_in_insts({"array"}, "ar ty", ARRAY_ARG_ord, fuzzer, json_data, lks_data)
    # util.get_type_in_insts({"vector"}, "ar ty", VECTOR_ARG_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"vector", "array"}, "ar ty", ARRAY_VECTOR_ARG_ord, fuzzer, json_data, lks_data)

    util.get_type_in_insts({"i8"}, "st ty", I8_ST_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"i16"}, "st ty", I16_ST_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"i32"}, "st ty", I32_ST_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"i64"}, "st ty", I64_ST_ord, fuzzer, json_data, lks_data)
    # util.get_type_in_insts({"i128"}, "st ty", I128_ST_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"i32", "i64"}, "st ty", I32_I64_ST_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"i32", "i64", "i128"}, "st ty", I32_I64_I128_ST_ord, fuzzer, json_data, lks_data)
    # util.get_type_in_insts({"float"}, "st ty", FLOAT_ST_ord, fuzzer, json_data, lks_data)
    # util.get_type_in_insts({"double"}, "st ty", DOUBLE_ST_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"pointer"}, "st ty", POINTER_ST_ord, fuzzer, json_data, lks_data)
    # util.get_type_in_insts({"struct"}, "st ty", STRUCT_ST_ord, fuzzer, json_data, lks_data)
    # util.get_type_in_insts({"array"}, "st ty", ARRAY_ST_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"vector"}, "st ty", VECTOR_ST_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"array", "vector"}, "st ty", ARRAY_VECTOR_ST_ord, fuzzer, json_data, lks_data)

    # util.get_type_in_insts({"i8"}, "al ty", I8_AL_ord, fuzzer, json_data, lks_data)
    # util.get_type_in_insts({"i16"}, "al ty", I16_AL_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"i32"}, "al ty", I32_AL_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"i64"}, "al ty", I64_AL_ord, fuzzer, json_data, lks_data)
    # util.get_type_in_insts({"i128"}, "al ty", I128_AL_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"i32", "i64"}, "al ty", I32_I64_AL_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"i32", "i64", "i128"}, "al ty", I32_I64_I128_AL_ord, fuzzer, json_data, lks_data)
    # util.get_type_in_insts({"float"}, "al ty", FLOAT_AL_ord, fuzzer, json_data, lks_data)
    # util.get_type_in_insts({"double"}, "al ty", DOUBLE_AL_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"pointer"}, "al ty", POINTER_AL_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"struct"}, "al ty", STRUCT_AL_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"array"}, "al ty", ARRAY_AL_ord, fuzzer, json_data, lks_data)
    # util.get_type_in_insts({"vector"}, "al ty", VECTOR_AL_ord, fuzzer, json_data, lks_data)
    util.get_type_in_insts({"array", "vector"}, "al ty", ARRAY_VECTOR_AL_ord, fuzzer, json_data, lks_data)

    util.get_size(SIZE_ord, fuzzer, json_data, lks_data)
    util.get_bbs(BBs_ord, fuzzer, json_data, lks_data)
    util.get_inst_ratio("# cmp", CMPs_ord, fuzzer, json_data, lks_data)
    util.get_inst_ratio("# load", LOADs_ord, fuzzer, json_data, lks_data)
    util.get_inst_ratio("# store", STOREs_ord, fuzzer, json_data, lks_data)
    util.get_inst_ratio("# alloca", ALLOCAs_ord, fuzzer, json_data, lks_data)
    util.get_inst_ratio("# call", CALLs_ord, fuzzer, json_data, lks_data)
    util.get_inst_ratio(
        "# binaryOp",
        BINARYOPs_ord,
        fuzzer,
        json_data,
        lks_data)
    util.get_inst_ratio("# branch", BRANCHs_ord, fuzzer, json_data, lks_data)
    
    # util.get_cmps("str cmp", STR_CMPs_ord, fuzzer, json_data, lks_data)
    # util.get_cmps("mem cmp", MEM_CMPs_ord, fuzzer, json_data, lks_data)
    util.get_str_mem_cmps(STR_MEM_CMPs_ord, fuzzer, json_data, lks_data)
    util.get_cmps("int cmp", INT_CMPs_ord, fuzzer, json_data, lks_data)
    util.get_cmps("float cmp", FLOATs_CMPs_ord, fuzzer, json_data, lks_data)

    util.get_abc(ABC_ord, fuzzer, json_data, lks_data)
    util.get_cyclomatic(CYCLOMATIC_ord, fuzzer, json_data, lks_data)

    util.get_ne_mean_lv(NE_LV_MEAN_ord, fuzzer, json_data, lks_data)
    util.get_cm_gl(CM_GL_ord, fuzzer, json_data)
    util.get_cm_nz(CM_NZ_ord, fuzzer, json_data)


    # get_global_analy(fuzzer, json_data)
    API_stat(fuzzer, json_data)

def write_out(d, varname):
    s = {key.split("/")[0]: value for key, value in sorted(d.items(), key=lambda item: item[1])}
    
    unique_values = sorted(set(s.values()))
    dense_rank = {v: rank + 1 for rank, v in enumerate(unique_values)}

    # Applying the dense rank to the sorted dictionary
    result_dict = {k: (dense_rank[v], v) for k, v in s.items()}
    print(varname)
    with open(os.path.join("../../data", "{}.txt".format(varname)), "w") as f:
        f.write(json.dumps(result_dict))


def get_extcalls(fuzzer, json_data):
    global EXTcall

    ext_calls = set()
    for fn_name in json_data:
        if "AP" in json_data[fn_name].keys():
            all_calls = json_data[fn_name]["AP"].keys()
            for call in all_calls:
                if not (call in json_data):
                    ext_calls.add(
                        util.remove_arguments(
                            demangle(call)).removesuffix("\n"))
    EXTcall |= ext_calls


ALL_apis = dict()


def API_stat(fuzzer, json_data):
    global ALL_apis

    for _, data in json_data.items():
        if "AP" in data.keys():
            for fnname, val in data["AP"].items():
                simplified = util.remove_arguments(
                    demangle(fnname)).removesuffix('\n')
                if simplified not in ALL_apis:
                    ALL_apis[simplified] = {f: 0 for f in fuzzer_list}
                    ALL_apis[simplified][fuzzer] = data["AP"][fnname]
                else:
                    ALL_apis[simplified][fuzzer] += data["AP"][fnname]

    print(len(ALL_apis))


def get_global_analy(json_data):
    global FU_data
    global HAP_data
    global MEAP_data
    global STW_data
    global STARG_data
    global CMPTY_data
    global STOTY_data
    global LOATY_data
    global ALLTY_data
    global ARGTY_data

    for _, data in json_data.items():
        if "AP" in data.keys():
            FU_demangled = set()

            for fnname in data["AP"].keys():
                demangled = demangle(fnname)
                # print("FNNAME", fnname)
                # print("DEMANGLE", demangled)
                simplified = util.remove_arguments(demangled)
                FU_demangled.add(simplified)
            # print(len(data["AP"].keys()))
            FU_data |= FU_demangled
        if "h AP" in data.keys():
            HAP_data |= data["h AP"].keys()
        if "m AP" in data.keys():
            MEAP_data |= data["m AP"].keys()
        if "wr st" in data.keys():
            STW_data |= data["wr st"].keys()
        if "str arg" in data.keys():
            STARG_data |= data["str arg"].keys()
        if "cm ty" in data.keys():
            CMPTY_data |= data["cm ty"].keys()
        if "st ty" in data.keys():
            STOTY_data |= data["st ty"].keys()
        if "l ty" in data.keys():
            LOATY_data |= data["l ty"].keys()
        if "al ty" in data.keys():
            ALLTY_data |= data["al ty"].keys()
        if "ar ty" in data.keys():
            ARGTY_data |= data["ar ty"].keys()


# white_list = util.init_white_list(fuzzer_list)

for fuzzer in fuzzer_list:
    fuzzer_dir = "/".join(fuzzer.split("/")[:2])
    analysis = os.path.join(fuzzer_dir, "analysis")
    ddg = os.path.join(fuzzer_dir, "ddg")
    table = os.path.join(fuzzer_dir, "table")

    analysis_list = []
    for root, _, files in os.walk(os.path.join(os.getcwd(), analysis)):
        for file_name in files:
            if ".json" in file_name:
                name = file_name.removesuffix(".json")
                di = os.path.join(root, name)
                js = di + ".json"
                lks = di + ".lks"
                cfg = di + ".cfg"
                analysis_list.append((js, lks, cfg))

    ddg_list = []
    for root, _, files in os.walk(os.path.join(os.getcwd(), ddg)):
        for file_name in files:
            if ".ddg" in file_name:
                full = os.path.join(root, file_name)
                ddg_list.append(full)

    table_list = []
    for root, _, files in os.walk(os.path.join(os.getcwd(), table)):
        for file_name in files:
            if ".table" in file_name:
                full = os.path.join(root, file_name)
                table_list.append(full)

    # print(di, "\n")
    json_read(fuzzer, analysis_list, ddg_list, table_list)
    # input()


names = [
    "I8_CMPs_ord",
    "I16_CMPs_ord",
    "I32_CMPs_ord",
    "I64_CMPs_ord",
    # "I128_CMPs_ord",
    "I32_I64_CMPs_ord",
    "I32_I64_I128_CMPs_ord",
    # "FLOAT_CMPs_ord",
    # "DOUBLE_CMPs_ord",
    "POINTER_CMPs_ord",
    # "STRUCT_CMPs_ord",
    # "ARRAY_CMPs_ord",
    "VECTOR_CMPs_ord",
    "ARRAY_VECTOR_CMPs_ord",
    "I8_ARG_ord",
    "I16_ARG_ord",
    "I32_ARG_ord",
    "I64_ARG_ord",
    # "I128_ARG_ord",
    "I32_I64_ARG_ord",
    "I32_I64_I128_ARG_ord",
    # "FLOAT_ARG_ord",
    # "DOUBLE_ARG_ord",
    "POINTER_ARG_ord",
    # "STRUCT_ARG_ord",
    # "ARRAY_ARG_ord",
    # "VECTOR_ARG_ord",
    #"ARRAY_VECTOR_ARG_ord",
    "I8_ST_ord",
    "I16_ST_ord",
    "I32_ST_ord",
    "I64_ST_ord",
    # "I128_ST_ord",
    "I32_I64_ST_ord",
    "I32_I64_I128_ST_ord",
    # "FLOAT_ST_ord",
    # "DOUBLE_ST_ord",
    "POINTER_ST_ord",
    # "STRUCT_ST_ord",
    # "ARRAY_ST_ord",
    "VECTOR_ST_ord",
    # "ARRAY_VECTOR_ST_ord",
    # "I8_AL_ord",
    # "I16_AL_ord",
    "I32_AL_ord",
    "I64_AL_ord",
    # "I128_AL_ord",
    "I32_I64_AL_ord",
    "I32_I64_I128_AL_ord",
    # "FLOAT_AL_ord",
    # "DOUBLE_AL_ord",
    "POINTER_AL_ord",
    "STRUCT_AL_ord",
    "ARRAY_AL_ord",
    # "VECTOR_AL_ord",
    "ARRAY_VECTOR_AL_ord",
    "BBs_ord",
    "SIZE_ord",
    "CMPs_ord",
    "LOADs_ord",
    "STOREs_ord",
    "CALLs_ord",
    "ALLOCAs_ord",
    "BRANCHs_ord",
    "BINARYOPs_ord",
    "INT_CMPs_ord",
    "FLOATs_CMPs_ord",
    # "MEM_CMPs_ord",
    # "STR_CMPs_ord",
    "STR_MEM_CMPs_ord",
    "I64_CMPs_ord",
    "m_AP_ord",
    "h_AP_ord",
    "CYCLOMATIC_ord",
    "ABC_ord",
    "NE_LV_MEAN_ord",
    "AVG_MIN_PATH_CFGs",
    "MIN_PATH_CFGs",
    "CYCLE_CFGs",
    "NODE_DDGs",
    "EDGE_DDGs",
    "CM_GL_ord",
    "CM_NZ_ord"
    ]

def check_v(di):
    hm = dict()
    for key, value in di.items():
        if value in hm.keys():
            hm[value] += 1
        else:
            hm[value] = 1
    ma = 0
    k = 0
    for key, value in hm.items():
        if value > ma:
            ma = value
            k = key

    print(k, ma)




for var in names:
    di = eval(var)
    check_v(di)
    write_out(di, var)
    print()
'''
print("GO")
maxlen = 0
minlen = 100000000
for fnname in ALL_apis:
    if len(fnname) > maxlen:
        maxlen = len(fnname)

substr_map = dict()
for k in range(4, maxlen + 1):
    print(k)
    for fnname, freq_dict in ALL_apis.items():
        for start in range(len(fnname) - k + 1):
            substr = fnname[start:start + k]
            if substr not in substr_map:
                substr_map[substr] = {f: 0 for f in fuzzer_list}
                for fuzzer, value in freq_dict.items():
                    substr_map[substr][fuzzer] += value
            else:
                for fuzzer, value in freq_dict.items():
                    substr_map[substr][fuzzer] += value
print(len(substr_map))

hist = dict()
for substr in list(substr_map.keys()):
    total = 0
    occurence = 0
    for fuzzer in substr_map[substr]:
        total += substr_map[substr][fuzzer]
        if substr_map[substr][fuzzer] > 0:
            occurence += 1
    
    if occurence not in hist:
        hist[occurence] = 1
    else:
        hist[occurence] += 1
    if total <= 1 or occurence < 16:
        substr_map.pop(substr)


print("A", len(substr_map))
print(hist)
print(substr_map.keys())
with open("result.txt", "w") as res:
    res.write(json.dumps(substr_map))
'''
'''
print(len(EXTcall))
print(len(FU_data))
print(len(HAP_data))
print(len(MEAP_data))
print(len(STW_data))
print(len(STARG_data))
print(len(CMPTY_data))
print(len(STOTY_data))
print(len(LOATY_data))
print(len(ALLTY_data))
print(len(ARGTY_data))
print(EXTcall)
# print(INT2EXT_call)
'''
