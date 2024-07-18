import json
from bs4 import BeautifulSoup
import sys

urlbase0 = "https://storage.googleapis.com/fuzzbench-data/2023-05-22-libafl-var/coverage/reports/BENCHMARK/FUZZER/index.html"
urlbase1 = "https://storage.googleapis.com/fuzzbench-data/2023-06-02-libafl-var/coverage/reports/BENCHMARK/FUZZER/index.html"
urlbase2 = "https://storage.googleapis.com/fuzzbench-data/2023-09-25-libafl-grimoire/coverage/reports/BENCHMARK/FUZZER/index.html"

fuzzer_0 = [
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

fuzzer_1 = [
    "libafl_fuzzbench_ngram4",
    "libafl_fuzzbench_ngram8",
    "libafl_fuzzbench_naive_ctx",
]

fuzzer_2 = [
    "libafl_fuzzbench_grimoire",
]

benchmarks = [
    'bloaty_fuzz_target', 
    'curl_curl_fuzzer_http',
    'freetype2_ftfuzzer',
    'harfbuzz_hb-shape-fuzzer',
    'jsoncpp_jsoncpp_fuzzer',
    'lcms_cms_transform_fuzzer',
    'libjpeg-turbo_libjpeg_turbo_fuzzer',
    'libpcap_fuzz_both',
    'libpng_libpng_read_fuzzer',
    'libxml2_xml',
    'libxslt_xpath',
    'mbedtls_fuzz_dtlsclient',
    'openh264_decoder_fuzzer',
    'openssl_x509',
    'openthread_ot-ip6-send-fuzzer',
    'proj4_proj_crs_to_crs_fuzzer',
    're2_fuzzer',
    'sqlite3_ossfuzz',
    'stb_stbi_read_fuzzer',
    'systemd_fuzz-link-parser',
    'vorbis_decode_fuzzer',
    'woff2_convert_woff2ttf_fuzzer',
    'zlib_zlib_uncompress_fuzzer'
]

import requests
from io import BytesIO
import re

result = dict()

def parse(html_content):
    # Parse the HTML content
    if "The specified key does not exist" in html_content:
        return None

    soup = BeautifulSoup(html_content, 'html.parser')

    # Find the row with the "Totals" text
    total_row = None
    rows = soup.find_all('tr')
    for row in rows:
        if 'Totals' in row.text:
            total_row = row
            break
    # Extract the coverage percentages from the "Totals" row
    if total_row:
        coverages = total_row.find_all('td')[1:]
        function_coverage = coverages[0].text.strip()
        line_coverage = coverages[1].text.strip()
        region_coverage = coverages[2].text.strip()
        branch_coverage = coverages[3].text.strip()

        # Create a dictionary with the coverage percentages
        data = {
            'function coverage': function_coverage,
            # 'line coverage': line_coverage,
            # 'region coverage': region_coverage,
            # 'branch coverage': branch_coverage
        }

        for key, value in data.items():
            # print(value)
            match = re.search(r"(\d+\.\d+)%", value)
            if match:
                percentage = float(match.group(1))
                data[key] = percentage

        # Print the JSON output
        return data
    else:
        print("Failed to parse")
        exit(0)


def fetch(fuzzer_list, u):
    for fuzzer in fuzzer_list:
        print("Fetching ", fuzzer)
        for benchmark in benchmarks:
            copied = u[:]
            copied = copied.replace("FUZZER", fuzzer)
            copied = copied.replace("BENCHMARK", benchmark)

            content = None
            try:
                response = requests.get(copied)
                buf = BytesIO(response.content)
                content = buf.getvalue().decode("utf-8")
            except:
                print("Failed to fetch")
                exit(0)

            parsed = parse(content)

            if fuzzer in result:
                result[fuzzer][benchmark] = parsed
            else:
                result[fuzzer] = dict()
                result[fuzzer][benchmark] = parsed

fetch(fuzzer_0, urlbase0)
fetch(fuzzer_1, urlbase1)
fetch(fuzzer_2, urlbase2)

print(result)

with open('function-cov.json', 'w') as fp:
    json.dump(result, fp)
