#!/usr/bin/env python

import sys
import os
import re

PARSED_DUMPS_DIR = 'paths/'
RESULT_OUTPUT = 'prefix_asns.out'
first_octet = re.compile(r"^[^.|:]*")


# Remove duplicate asns in a row
# [1, 1, 2, 3, 3, 3] -> [1, 2, 3]
def dedup(asn_path):
    i = len(asn_path) - 2
    while i > 0:
        if asn_path[i] == asn_path[i - 1]:
            asn_path = asn_path[0:i] + asn_path[i+1:]
        i -= 1
    return asn_path

def find_common_suffixes(prefix_asn_paths):
    common_asn_suffix = dict()
    for prefix, asn_lists in prefix_asn_paths.items():
        asn_lists = [dedup(asn_list.split(' ')) for asn_list in asn_lists] # preprocess
        asn_lists = [asn_list for asn_list in asn_lists if asn_list != [] and set(asn_list) != ['']] # this very rarely happens in dumps
        asn_lists.sort(key = len)
        cur_asn_suffix = asn_lists[0] # represents the common sub-path (from the end) of asns to a prefix
        for asn_list in asn_lists[1:]:
            if cur_asn_suffix == asn_list:
                continue
            if cur_asn_suffix[-1] != asn_list[-1]: # multi-homed
                break
            cur_asn_suffix_len = len(cur_asn_suffix)
            for i in range(1, cur_asn_suffix_len): # position from the end
                if cur_asn_suffix[len(cur_asn_suffix) - i - 1] != asn_list[len(asn_list) - i - 1]:
                    cur_asn_suffix = cur_asn_suffix[len(cur_asn_suffix) - i:]
                    break
        common_asn_suffix[prefix] = cur_asn_suffix
    return common_asn_suffix


last_read_line = dict() # per file to track chunk processing
FILES = os.listdir(PARSED_DUMPS_DIR)
for file_name in FILES:
    last_read_line[file_name] = 0


def process_chunk(current_chunk_start, step, end, processing_ipv4):
    print(("Working on chunk %i %i" % (current_chunk_start, current_chunk_start + step)), flush=True)
    announcements = dict()
    for file_name in FILES:
        print('Reading file: ', file_name, flush=True)
        with open(PARSED_DUMPS_DIR + file_name, "r") as file:
            for _ in range(last_read_line[file_name]):
                next(file)
            line_number = last_read_line[file_name]
            for line in file:
                line_number += 1
                announcement_data = re.sub(r'{[^>]+}', ' ', line.strip()) # removes {} sets in AS path
                announcement_data = announcement_data.split('|')
                prefix = announcement_data[0]
                first_oc = re.search(first_octet, prefix).group(0)
                asns = announcement_data[1]
                is_ipv4 = prefix.count(':') == 0
                if processing_ipv4 != is_ipv4:
                    continue

                if first_oc == '' and processing_ipv6: # for ipv6
                    first_oc = 0

                if int(first_oc) > current_chunk_start + step: # passed current chunk
                    last_read_line[file_name] = line_number
                    break
                # if int(first_oc) < i: # current chunk is ahead
                #     continue
                announcements.setdefault(prefix, set()).add(asns)
    res = find_common_suffixes(announcements)
    announcements.clear()
    dump_result(res)
    res.clear()

MAX_IPv4 = 2 << 7
MAX_IPv6 = 2 << 16
def process_files():
    SMALL_STEP = 2 << 4 # for ips with the first octet less than MAX_IPv4 (all ipv4 and some ipv6)
    BIG_STEP =  2 << 12 # for the rest of ipv6
    # The assumption is that the records are ordered by ip, but ipv6 can appear here and there
    for i in range(0, MAX_IPv4, SMALL_STEP): # process ip range chunks so that memory is not filled
        process_chunk(i, SMALL_STEP, MAX_IPv4, True)

    for i in range(0, MAX_IPv6, BIG_STEP): # process ip range chunks so that memory is not filled
        process_chunk(i, BIG_STEP, MAX_IPv6, False)

def dump_result(prefix_unique_asn_suffixes):
    with open(RESULT_OUTPUT, 'a') as file:
        for prefix, unique_asn_suffix in prefix_unique_asn_suffixes.items():
            if unique_asn_suffix[0] == '':
                print(unique_asn_suffix)
                assert(False)
            file.write("%s AS%s\n" % (prefix, unique_asn_suffix[0]))

res = process_files()
# dump_result(res)
