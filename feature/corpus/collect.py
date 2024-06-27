import os

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

import json

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


def write_out(d, varname):
    s = {key.split("/")[0]: value for key, value in sorted(d.items(), key=lambda item: item[1])}
    
    unique_values = sorted(set(s.values()))
    dense_rank = {v: rank + 1 for rank, v in enumerate(unique_values)}

    # Applying the dense rank to the sorted dictionary
    result_dict = {k: (dense_rank[v], v) for k, v in s.items()}
    print(varname)
    with open(os.path.join("../../data", "{}.txt".format(varname)), "w") as f:
        f.write(json.dumps(result_dict))

CORPUS_ord = dict()
CORPUS_SZ_ord = dict()
FN_COV_ord = dict()
LN_COV_ord = dict()
RG_COV_ord = dict()
BR_COV_ord = dict()

for fuzzer in fuzzer_list:
    fuzzer_dir = "/".join(fuzzer.split("/")[:2])
    counter = 0
    size = 0

    report_dir = os.path.join(fuzzer_dir, "report")
    index = os.path.join(report_dir, "index.html")

    with_total = 0
    with open(index, 'r') as f:
        lines = f.readlines()
        for line in lines:
            if "Total" in line:
                with_total += 1
                line = line.split("Total")[1]
                line = line.split("Files which")[0]
                line = line.split("%")[:-1]
                line = [(x.split(' ')[-1]) for x in line]
                FN_COV_ord[fuzzer] = float(line[0])
                LN_COV_ord[fuzzer] = float(line[1])
                RG_COV_ord[fuzzer] = float(line[2])
                BR_COV_ord[fuzzer] = float(line[3])

                print(line)
    assert (with_total == 1)

    for root, dirs, files in os.walk(os.path.join(fuzzer_dir, "seeds")):
        for file in files:
            relpath = os.path.join(root, file)
            counter += 1
            size += os.path.getsize(relpath)
    CORPUS_ord[fuzzer] = counter
    CORPUS_SZ_ord[fuzzer] = size / counter

names = ["CORPUS_ord", "CORPUS_SZ_ord", "FN_COV_ord", "LN_COV_ord", "RG_COV_ord", "BR_COV_ord"]

for var in names:
    di = eval(var)
    check_v(di)
    write_out(di, var)
