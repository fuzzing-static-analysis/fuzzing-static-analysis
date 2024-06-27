import angr
import os
import logging

from subprocess import check_output

name_list = [
    "bloaty_fuzz_target/out/fuzz_target",
    "curl_curl_fuzzer_http/out/curl_fuzzer_http",
    "freetype2_ftfuzzer/out/ftfuzzer",
    "harfbuzz_hb/out/hb-shape-fuzzer",
    "jsoncpp_jsoncpp_fuzzer/out/jsoncpp_fuzzer",
    "lcms_cms_transform_fuzzer/out/cms_transform_fuzzer",
    "libjpeg/out/libjpeg_turbo_fuzzer",
    "libpcap_fuzz_both/out/fuzz_both",
    "libpng_libpng_read_fuzzer/out/libpng_read_fuzzer",
    "libxml2_xml/out/xml",
    "libxslt_xpath/out/xpath",
    "mbedtls_fuzz_dtlsclient/out/fuzz_dtlsclient",
    "openh264_decoder_fuzzer/out/decoder_fuzzer",
    "openssl_x509/out/x509",
    "openthread_ot/out/ot-ip6-send-fuzzer",
    "proj4_proj_crs_to_crs_fuzzer/out/proj_crs_to_crs_fuzzer",
    "php_php/out/php-fuzz-parser",
    "re2_fuzzer/out/fuzzer",
    "sqlite3_ossfuzz/out/ossfuzz",
    "stb_stbi_read_fuzzer/out/stbi_read_fuzzer",
    "systemd_fuzz/out/fuzz-link-parser",
    "vorbis_decode_fuzzer/out/decode_fuzzer",
    "woff2_convert_woff2ttf_fuzzer/out/convert_woff2ttf_fuzzer",
    "zlib_zlib_uncompress_fuzzer/out/zlib_uncompress_fuzzer",
]

common = set()

for name in name_list:
    proj = angr.Project(name)
    counter = 0
    func_list = []
    for sym in proj.loader.symbols:
        if sym.owner == proj.loader.main_object and sym.is_function:

            demangled = str(check_output(
                ["c++filt", "-p", sym.name]), encoding='utf-8')

            if demangled.startswith("std::") or demangled.startswith("__sanitizer") or demangled.startswith("__ubsan") or "libafl" in demangled or "serde::" in demangled \
                    or "core::" in demangled or "alloc::" in demangled or "virtual link" in demangled or "hashbrown::" in demangled \
                    or "gimli::" in demangled or "rustc_demangle::" in demangled or "compiler_builtins::" in demangled or "addr2line::" in demangled \
                    or "ubsan" in demangled or demangled.startswith("_$LT$bool$") or demangled.startswith("_sancov") or demangled.startswith("__llvm") \
                    or demangled.startswith("__rust"):
                pass
            else:

                if "std::" in demangled:
                    print(demangled)

                func_list.append(sym.name)
                counter += 1
            # print(type(demangled), demangled)
        
        if sym.is_function and sym.owner != proj.loader.main_object:
            print(sym.name)
    if name == "bloaty_fuzz_target/out/fuzz_target":
        common = set(func_list)
    else:
        common = common & set(func_list)

    wr = os.path.join(os.path.dirname(name), "func.txt")
    with open(wr, 'w') as ou:
        ou.write("\n".join(func_list))
    print(name, counter, os.path.dirname(name))

print(common)
