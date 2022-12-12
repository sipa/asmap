# Copyright (c) 2022 Pieter Wuille
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import argparse
import sys
import ipaddress
import math

import asmap

def load_file(input_file, state=None):
    try:
        contents = input_file.read()
    except OSError as err:
        sys.exit("Input file '%s' cannot be read: %s." % (input_file.name, err.strerror))
    try:
        bin_asmap = asmap.ASMap.from_binary(contents)
    except ValueError:
        bin_asmap = None
    txt_error = None
    entries = None
    try:
        txt_contents = str(contents, encoding="utf-8")
    except UnicodeError:
        txt_error = "invalid UTF-8"
        txt_contents = None
    if txt_contents is not None:
        entries = []
        for line in txt_contents.split("\n"):
            idx = line.find('#')
            if idx >= 0:
                line = line[:idx]
            line = line.lstrip(' ').rstrip(' \t\r\n')
            if len(line) == 0:
                continue
            fields = line.split(' ')
            if len(fields) != 2:
                txt_error = "unparseable line '%s'" % line
                entries = None
                break
            prefix, asn = fields
            if len(asn) <= 2 or asn[:2] != "AS" or any(c < '0' or c > '9' for c in asn[2:]):
                txt_error = "invalid ASN '%s'" % asn
                entries = None
                break
            try:
                net = ipaddress.ip_network(prefix)
            except ValueError:
                txt_error = "invalid network '%s'" % prefix
                entries = None
                break
            entries.append((asmap.net_to_prefix(net), int(asn[2:])))
    if entries is not None and bin_asmap is not None and len(contents) > 0:
        sys.exit("Input file '%s' is ambiguous." % input_file.name)
    if entries is not None:
        if state is None:
            state = asmap.ASMap()
        state.update_multi(entries)
        return state
    if bin_asmap is not None:
        if state is None:
            return bin_asmap
        sys.exit("Input file '%s' is binary, and cannot be applied as a patch." % input_file.name)
    sys.exit("Input file '%s' is neither a valid binary asmap file nor valid text input (%s)." % (input_file.name, txt_error))


def save_binary(output_file, state, fill):
    contents = state.to_binary(fill=fill)
    try:
        output_file.write(contents)
        output_file.close()
    except OSError as err:
        sys.exit("Output file '%s' cannot be written to: %s." % (output_file.name, err.strerror))

def save_text(output_file, state, fill, overlapping):
    for prefix, asn in state.to_entries(fill=fill, overlapping=overlapping):
        net = asmap.prefix_to_net(prefix)
        try:
            print("%s AS%i" % (net, asn), file=output_file)
        except OSError as err:
            sys.exit("Output file '%s' cannot be written to: %s." % (output_file.name, err.strerror))
    try:
        output_file.close()
    except OSError as err:
        sys.exit("Output file '%s' cannot be written to: %s." % (output_file.name, err.strerror))

def main():
    parser = argparse.ArgumentParser(description="Tool for performing various operations on texual and binary asmap files.")
    subparsers = parser.add_subparsers(title="valid subcommands", dest="subcommand")

    parser_encode = subparsers.add_parser("encode", help="convert asmap data to binary format")
    parser_encode.add_argument('-f', '--fill', dest="fill", default=False, action="store_true",
                               help="permit reassigning undefined network ranges arbitrarily to reduce size")
    parser_encode.add_argument('infile', nargs='?', type=argparse.FileType('rb'), default=sys.stdin.buffer,
                               help="input asmap file (text or binary); default is stdin")
    parser_encode.add_argument('outfile', nargs='?', type=argparse.FileType('wb'), default=sys.stdout.buffer,
                               help="output binary asmap file; default is stdout")

    parser_decode = subparsers.add_parser("decode", help="convert asmap data to text format")
    parser_decode.add_argument('-f', '--fill', dest="fill", default=False, action="store_true",
                               help="permit reassigning undefined network ranges arbitrarily to reduce length")
    parser_decode.add_argument('-n', '--nonoverlapping', dest="overlapping", default=True, action="store_false",
                               help="output strictly non-overallping network ranges (increases output size)")
    parser_decode.add_argument('infile', nargs='?', type=argparse.FileType('rb'), default=sys.stdin.buffer,
                               help="input asmap file (text or binary); default is stdin")
    parser_decode.add_argument('outfile', nargs='?', type=argparse.FileType('w'), default=sys.stdout,
                               help="output text file; default is stdout")

    parser_diff = subparsers.add_parser("diff", help="compute the difference between two asmap files")
    parser_diff.add_argument('-i', '--ignore-unassigned', dest="ignore_unassigned", default=False, action="store_true",
                             help="ignore unassigned ranges in the first input (useful when second input is filled)")
    parser_diff.add_argument('-u', '--unified', dest="unified", default=False, action="store_true",
                             help="output diff in 'unified' format (with +- lines)")
    parser_diff.add_argument('infile1', type=argparse.FileType('rb'),
                             help="first file to compare (text or binary)")
    parser_diff.add_argument('infile2', type=argparse.FileType('rb'),
                             help="second file to compare (text or binary)")

    args = parser.parse_args()
    if args.subcommand is None:
        parser.print_help()
    elif args.subcommand == "encode":
        state = load_file(args.infile)
        save_binary(args.outfile, state, fill=args.fill)
    elif args.subcommand == "decode":
        state = load_file(args.infile)
        save_text(args.outfile, state, fill=args.fill, overlapping=args.overlapping)
    elif args.subcommand == "diff":
        state1 = load_file(args.infile1)
        state2 = load_file(args.infile2)
        ipv4_changed = 0
        ipv6_changed = 0
        for prefix, old_asn, new_asn in state1.diff(state2):
            if args.ignore_unassigned and old_asn == 0:
                continue
            net = asmap.prefix_to_net(prefix)
            if isinstance(net, ipaddress.IPv4Network):
                ipv4_changed += 1 << (32 - net.prefixlen)
            elif isinstance(net, ipaddress.IPv6Network):
                ipv6_changed += 1 << (128 - net.prefixlen)
            if new_asn == 0:
                print("# %s was AS%i" % (net, old_asn))
            elif old_asn == 0:
                print("%s AS%i # was unassigned" % (net, new_asn))
            else:
                print("%s AS%i # was AS%i" % (net, new_asn, old_asn))
        print(
            "# %i%s IPv4 addresses changed; %i%s IPv6 addresses changed"
            % (
                ipv4_changed,
                "" if ipv4_changed == 0 else " (2^%.2f)" % math.log2(ipv4_changed),
                ipv6_changed,
                "" if ipv6_changed == 0 else " (2^%.2f)" % math.log2(ipv6_changed),
            )
        )
    else:
        parser.print_help()
        sys.exit("No command provided.")

if __name__ == '__main__':
    main()
