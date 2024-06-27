from itertools import groupby
import os
import networkx as nx


def remove_arguments(template):
    template = template.replace("->", "?1")
    template = template.replace("operator<<", "?4")
    template = template.replace("operator>>", "?5")
    template = template.replace("operator>", "?2")
    template = template.replace("operator<", "?3")

    res = []
    curr_depth = 0
    for _, g in groupby(template, lambda x: x in ['<', '>']):
        text = ''.join(g)  # rebuild the group as a string

        for c in text:
            if c == '<':
                curr_depth += 1

            if curr_depth == 0:
                res.append(c)

            if c == '>':
                curr_depth -= 1

    assert (curr_depth == 0)

    final = ''.join(res)

    final = final.replace("?1", "->")
    final = final.replace("?4", "operator<<")
    final = final.replace("?5", "operator>>")
    final = final.replace("?2", "operator>")
    final = final.replace("?3", "operator<")

    return final  # rebuild the complete string


'''
def init_white_list(fuzzer_list):
    white_list = dict()
    # Build whitelist
    for fuzzer in fuzzer_list:
        whitelist = os.path.join(fuzzer, "whitelist.txt")
        res = set()
        with open(whitelist) as wl:
            for line in wl:
                dire = os.path.dirname(line.rstrip('\n'))
                res.add(dire)

        white_list[fuzzer] = res

    return white_list


def is_in_source(white_list, fuzzer, source):
    source = source.rstrip('.json')
    d = os.path.dirname(source)

    if source.startswith('/work') or source.startswith('/src/sqlite3/bld') or source.startswith("/src/libpcap/build") or source.startswith("/src/mbedtls/build"):
        return True

    return d in white_list[fuzzer]
'''


def get_table_features(fuzzer, order, _json_data, table):
    res = 0
    res2 = 0

    for fname, _data in table.items():
        if fname in table:
            res += table[fname]
            res2 += 1
    print(fuzzer, res, res2)
    order[fuzzer] = res / res2


def parse_ddg(ddg):
    ret = dict()
    for (source, sink) in ddg:
        fn_name, source_ptr = source.split(' ')
        sink_ptrs = sink.lstrip("deps: ").split(' ')
        if fn_name not in ret:
            G = nx.DiGraph()
            ret[fn_name] = G

        ret[fn_name].add_node(source_ptr)
        for sink_ptr in sink_ptrs:
            ret[fn_name].add_node(sink_ptr)
            ret[fn_name].add_edge(source_ptr, sink_ptr)
    return ret


def parse_cfg(cfg):
    ret = dict()
    for (fname, g) in cfg['edges'].items():
        sz = len(g)
        G = nx.DiGraph()
        for idx in range(0, sz):
            G.add_node(idx)

        for src, dsts in enumerate(g):
            for dst in dsts:
                G.add_edge(src, dst)
        ret[fname] = G

    return ret


def get_graph_features(fuzzer, what, order, json_data, graph):
    res = 0
    res2 = 0
    for fname, _data in json_data.items():
        if fname in graph:
            G = graph[fname]
            if what == "cycle":
                found = False
                try:
                    nx.find_cycle(G, orientation='original')
                except nx.NetworkXNoCycle:
                    found = True
                added = 1 if found else 0
                res += added
                res2 += 1
            elif what == "avgminpath":
                out0 = [node for node in G.nodes if G.out_degree(node) == 0]
                paths = nx.single_source_shortest_path(G, 0)
                lens = [len(paths[o]) for o in out0]
                for _dst in out0:
                    res += sum(lens) / len(lens)
                res2 += 1
            elif what == "minpath":
                out0 = [node for node in G.nodes if G.out_degree(node) == 0]
                paths = nx.single_source_shortest_path(G, 0)
                lens = [len(paths[o]) for o in out0]

                for _dst in out0:
                    res += min(lens)
                res2 += 1
            elif what == "node":
                res += len(G.nodes)
                res2 += 1
            elif what == "edge":
                res += len(G.edges)
                res2 += 1

    order[fuzzer] = res / res2


def parse_type(ty):
    if ty == "float":
        return "float"
    elif ty == "double":
        return "double"
    elif ty == "i128":
        return "i128"
    elif ty == "i64":
        return "i64"
    elif ty == "i32":
        return "i32"
    elif ty == "i16":
        return "i16"
    elif ty == "i8":
        return "i8"
    elif ty.endswith("*"):
        return "pointer"
    elif ty.startswith("%\"class.") or ty.startswith(r"%class."):
        return "struct"
    elif ty.startswith("%\"struct.") or ty.startswith(r"%struct"):
        return "struct"
    elif ty.startswith(r"%union") or ty.startswith("%\"union"):
        return "union"
    elif ty.startswith("{") and ty.endswith("}"):
        return "struct"
    elif ty.startswith("<") and ty.endswith(">"):
        return "vector"
    elif ty.startswith("[") and ty.endswith("]"):
        return "array"
    elif ty == "void":
        return "void"
    elif ty == "x86_fp80":
        return "x86_fp80"

    if ty.startswith("i") and ty[1].isnumeric():
        # i33 or i59 or whatever
        return ty

    if " (" in ty and ")" in ty:
        # func ptr
        # ret_type = parse_type(ty.split("(")[0].rstrip())
        return "func ptr"

    else:
        print(ty)
        raise Exception("Unknown type!")


def get_struct_member_freq(lks_data, struct_name):
    int_freq = 0
    ptr_freq = 0
    struct_freq = 0
    array_freq = 0
    double_freq = 0
    float_freq = 0
    total_freq = 0
    if struct_name == "":
        # This struct doesn't have any name
        # It could be std::make_pair() or something
        pass
    else:
        data = lks_data[struct_name]
        for (idnum, freq) in data["desc"]:
            total_freq += freq
            if idnum == 13:
                # int
                int_freq += freq
            elif idnum == 15:
                # ptr
                ptr_freq += freq
            elif idnum == 16:
                # struct
                struct_freq += freq
            elif idnum == 17:
                # array
                array_freq += freq
            elif idnum == 3:
                # double
                double_freq += freq
            elif idnum == 2:
                # float
                float_freq += freq
            else:
                raise Exception("Unknown Type")

    return (
        int_freq,
        ptr_freq,
        struct_freq,
        array_freq,
        double_freq,
        float_freq,
        total_freq)

def get_cm_gl(order, fuzzer, json_data):
    res = 0
    res2 = 0
    for _name, data in json_data.items():
        if "cm gl" in data.keys():
            for lv, freq in data["cm gl"].items():
                res += int(lv) * int(freq)
                res2 += int(freq)

    order[fuzzer] = (res / res2)


def get_cm_nz(order, fuzzer, json_data):
    res = 0
    res2 = 0
    for _name, data in json_data.items():
        if "cm gl" in data.keys():
            for lv, freq in data["cm nz"].items():
                res += int(lv) * int(freq)
                res2 += int(freq)

    order[fuzzer] = (res / res2)


def get_struct_freq_stats_per_wr_inst(select, order, fuzzer, json_data, lks_data):
    res = 0
    res2 = 0
    for _name, data in json_data.items():
        if "wr st" in data.keys():
            for ty, freq in data["wr st"].items():
                sz_tuple = get_struct_member_freq(lks_data, ty)
                res += freq * sz_tuple[select]
                res2 += freq
    order[fuzzer] = (res / res2)


def get_struct_double_float_freq_stats_per_wr_inst(order, fuzzer, json_data, lks_data):
    res = 0
    res2 = 0
    for _name, data in json_data.items():
        if "wr st" in data.keys():
            for ty, freq in data["wr st"].items():
                sz_tuple = get_struct_member_freq(lks_data, ty)
                res = res + freq * sz_tuple[4] + freq * sz_tuple[5]
                res2 += freq
    order[fuzzer] = (res / res2)


def get_struct_freq_stats_per_bb(select, order, fuzzer, json_data, lks_data):
    res = 0
    res2 = 0
    for _name, data in json_data.items():
        if "wr st" in data.keys():
            for ty, freq in data["wr st"].items():
                sz_tuple = get_struct_member_freq(lks_data, ty)
                res += freq * sz_tuple[select]
        if "# BBs" in data.keys():
            res2 += data["# BBs"]
    order[fuzzer] = (res / res2)


def get_struct_double_float_freq_stats_bb(order, fuzzer, json_data, lks_data):
    res = 0
    res2 = 0
    for _name, data in json_data.items():
        if "wr st" in data.keys():
            for ty, freq in data["wr st"].items():
                sz_tuple = get_struct_member_freq(lks_data, ty)
                res = res + freq * sz_tuple[4] + freq * sz_tuple[5]
        if "# BBs" in data.keys():
            res2 += data["# BBs"]
    order[fuzzer] = (res / res2)


def get_type_in_insts(typeset, inst, order, fuzzer, json_data, _lks_data):
    res = 0
    res2 = 0
    for _name, data in json_data.items():
        if inst in data.keys():
            for ty, freq in data[inst].items():
                t = parse_type(ty)
                if t in typeset:
                    res += freq
        if "# BBs" in data.keys():
            res2 += data["# BBs"]
    order[fuzzer] = (res / res2)


def test_aaa(order, fuzzer, json_data, _lks_data):
    res = 0
    res2 = 0
    for _name, data in json_data.items():
        if "cm ty" in data.keys():
            for ty, freq in data["cm ty"].items():
                if ty == "i32" or ty == "i64":
                    res += freq
        if "# BBs" in data.keys():
            res2 += data["# BBs"]
    order[fuzzer] = (res / res2)


def get_bbs(BBs_ord, fuzzer, json_data, _lks_data):
    res = 0
    for _, data in json_data.items():
        if "# BBs" in data.keys():
            v = data["# BBs"]
            res += v
    BBs_ord[fuzzer] = res


def get_cmps(select, order, fuzzer, json_data, _lks_data):
    res = 0
    res2 = 0

    for _name, data in json_data.items():
        if "cm cm" in data.keys():
            if select in data["cm cm"]:
                res += data["cm cm"][select]

        if "# BBs" in data.keys():
            res2 += data["# BBs"]
    order[fuzzer] = (res / res2)


def get_ne_mean_lv(NE_LV_MEAN_ord, fuzzer, json_data, _lks_data):
    v = 0
    count = 0
    for _name, data in json_data.items():
        if "ne lv" in data.keys():
            for lv, freq in data["ne lv"].items():
                v += int(lv) * int(freq)
                count += int(freq)

    NE_LV_MEAN_ord[fuzzer] = (v / count)


def get_str_mem_cmps(STR_MEM_CMPs_ord, fuzzer, json_data, _lks_data):
    res = 0
    res2 = 0

    for _name, data in json_data.items():
        if "cm cm" in data.keys():
            if "mem cmp" in data["cm cm"]:
                res += data["cm cm"]["mem cmp"]
            if "str cmp" in data["cm cm"]:
                res += data["cm cm"]["str cmp"]

        if "# BBs" in data.keys():
            res2 += data["# BBs"]

    STR_MEM_CMPs_ord[fuzzer] = (res / res2)


def get_abc(ABC_ord, fuzzer, json_data, _lks_data):
    res = 0
    res2 = 0
    for _name, data in json_data.items():
        if "ABC metric" in data.keys():
            res += data["ABC metric"]

        if "# BBs" in data.keys():
            res2 += data["# BBs"]
    ABC_ord[fuzzer] = (res / res2)


def get_cyclomatic(CYCLOMATIC_ord, fuzzer, json_data, _lks_data):
    res = 0
    res2 = 0
    for _name, data in json_data.items():
        if "cyclomatic" in data.keys():
            res += data["cyclomatic"]

        if "# BBs" in data.keys():
            res2 += data["# BBs"]
    CYCLOMATIC_ord[fuzzer] = res / res2


def get_inst_ratio(select, order, fuzzer, json_data, _lks_data):
    res = 0
    res2 = 0
    for _name, data in json_data.items():
        if select in data.keys():
            res += data[select]

        if "# BBs" in data.keys():
            res2 += data["# BBs"]

    order[fuzzer] = (res / res2)


def get_APs(select, order, fuzzer, json_data, _lks_data):
    res = 0
    res2 = 0
    for _name, data in json_data.items():
        if select in data.keys():
            for _k, v in data[select].items():
                res += v

        if "# BBs" in data.keys():
            res2 += data["# BBs"]

    order[fuzzer] = (res / res2)


def get_size(SIZE_ord, fuzzer, _json_data, _lks_data):
    binary_file = os.path.join("../../coverage_binary/result_lto", fuzzer)
    sz = os.path.getsize(binary_file)
    SIZE_ord[fuzzer] = sz


def test():
    _TEST0 = "a<<<>>>b"
    _TEST1 = "hb_vector_t<hb_aat_map_builder_t::feature_event_t, false>::alloc(unsigned int, bool)"
    _TEST2 = "std::__1::map<std::__1::pair<osgeo::proj::io::AuthorityFactory::ObjectType, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > >, std::__1::list<std::__1::pair<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > >, std::__1::allocator<std::__1::pair<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > > > >, std::__1::less<std::__1::pair<osgeo::proj::io::AuthorityFactory::ObjectType, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > > >, std::__1::allocator<std::__1::pair<std::__1::pair<osgeo::proj::io::AuthorityFactory::ObjectType, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > > const, std::__1::list<std::__1::pair<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > >, std::__1::allocator<std::__1::pair<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > > > > > > >::find(std::__1::pair<osgeo::proj::io::AuthorityFactory::ObjectType, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > > const&)"
    _TEST3 = "std::__1::unique_ptr<bloaty::ObjectFile, std::__1::default_delete<bloaty::ObjectFile> >::operator->"
    _TEST4 = "std::__1::operator< <char, std::__1::char_traits<char>, std::__1::allocator<char> >"
    _TEST5 = "hb_sanitize_context_t::_dispatch<AAT::ClassTable<OT::IntType<unsigned char, 1u> >>"
    # Test the function
    # print(remove_arguments(TEST0))
    # print(remove_arguments(TEST1))
    # print(remove_arguments(TEST2))
    # print(remove_arguments(TEST3))
    # print(remove_arguments(TEST4))
    # print(remove_arguments(TEST5))


if __name__ == '__main__':
    test()
