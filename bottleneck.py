import mrtparse
import ipaddress
import sys
import copy

def net_sorting_key(net):
    if isinstance(net, ipaddress.IPv4Network):
        return (0xffff00000000 + int.from_bytes(net.network_address.packed, 'big'), net.prefixlen + 96)
    elif isinstance(net, ipaddress.IPv6Network):
        return (int.from_bytes(net.network_address.packed, 'big'), net.prefixlen)
    else:
        raise NotImplementedError("Can only sort IPv4Network and IPv6Network")

def parse_path_segments(segs):
    ret = []
    for seg in segs:
        seg_t = list(seg['type'])[0]
        if seg_t == mrtparse.AS_PATH_SEG_T['AS_SEQUENCE']:
            ret.extend(int(x) for x in seg['value'])
        elif seg_t == mrtparse.AS_PATH_SEG_T['AS_SET']:
            pass
        elif seg_t == mrtparse.AS_PATH_SEG_T['AS_CONFED_SEQUENCE']:
            raise NotImplementedError("AS_CONFED_SEQUENCE path segments are not implemented")
        elif seg_t == mrtparse.AS_PATH_SEG_T['AS_CONFED_SET']:
            raise NotImplementedError("AS_CONFED_SET path segments are not implemented")
        else:
            raise NotImplementedError("Unknown path segment type %i" % seg_t)
    return ret

def valid_asn(asn, net):
    if asn == 0 or asn == 65535 or (asn >= 65552 and asn <= 131072) or asn == 4294967295:
        print("Skipping reserved AS%i (RFC1930) for network %s" % (asn, net))
    elif asn == 23456:
        print("Skipping transition AS%i (RFC6793) for network %s" % (asn, net))
    elif (asn >= 64496 and asn <= 64511) or (asn >= 65536 and asn <= 65551):
        print("Skipping documentation AS%i (RFC4893,RFC5398) for network %s" % (asn, net))
    elif (asn >= 64512 and asn <= 65534) or (asn >= 4200000000 and asn <= 4294967294):
        print("Skipping private AS%i (RFC5398,RFC6996) for network %s" % (asn, net))
    else:
        return True
    return False

def parse_path(attrs):
    as_path = []
    as4_path = []
    for attr in attrs:
        attr_t = list(attr['type'])[0]
        if attr_t == mrtparse.BGP_ATTR_T['AS_PATH']:
            as_path = parse_path_segments(attr['value'])
        elif attr_t == mrtparse.BGP_ATTR_T['AS_PATH4']:
            as4_path = parse_path_segments(attr['value'])
    assert len(as4_path) <= len(as_path)
    return as_path[:len(as_path) - len(as4_path)] + as4_path

def accept_net(net):
    if net.is_multicast:
        print("Skipping multicast network %s" % net)
    elif net.is_private:
        print("Skipping private network %s" % net)
    elif net.is_unspecified:
        print("Skipping unspecified network %s" % net)
    elif net.is_reserved:
        print("Skipping reserved network %s" % net)
    elif net.is_loopback:
        print("Skipping loopback network %s" % net)
    elif net.is_link_local:
        print("Skipping link-local network %s" % net)
    elif not net.is_global:
        print("Skipping non-global network %s" % net)
    elif net.prefixlen == 0:
        print("Skipping entire network %s" % net)
#    elif net.prefixlen > 48 and isinstance(net, ipaddress.IPv6Network):
#        print("Skipping IPv6 range smaller than a /48: %s" % net)
#    elif net.prefixlen > 24 and isinstance(net, ipaddress.IPv4Network):
#        print("Skipping IPv4 range smaller than a /24: %s" % net)
    else:
        return True
    return False

def merge_path(ret, net, path):
    assert len(path) > 0
    asn = path[-1]
    if net not in ret:
        ret[net] = {asn: (path, 1)}
    else:
        old_paths = ret[net]
        if asn not in old_paths:
            old_paths[asn] = (path, 1)
        else:
            old_path, old_count = old_paths[asn]
            common_len = 0
            while common_len < len(old_path) and common_len < len(path):
                if old_path[-common_len - 1] == path[-common_len - 1]:
                    common_len += 1
                else:
                    break
            old_paths[asn] = (old_path[-common_len:], old_count + 1)
    return True

def process_file(f, res):
    i = 0
    entries = 0
    rel_entries = 0
    ribs = 0
    rep_ribs = 0
    for entry in mrtparse.Reader(f):
        entries += 1
        data = entry.data
        t = list(data['type'])[0]
        if t == mrtparse.MRT_T['TABLE_DUMP']:
            rel_entries += 1
            netstr = "%s/%i" % (data['prefix'], data['prefix_length'])
            try:
                net = ipaddress.ip_network(netstr, strict=True)
            except ValueError:
                net = None
            if net is None:
                raise ValueError("Cannot parse network %s" % netstr)
            if accept_net(net):
                ribs += 1
                as_path = parse_path(data['path_attributes'])
                if len(as_path) == 0:
                    print("Skipping empty path for %s" % net)
                elif valid_asn(as_path[-1], net):
                    merge_path(res, net, as_path)
        elif t == mrtparse.MRT_T['TABLE_DUMP_V2']:
            st = list(data['subtype'])[0]
            if st == mrtparse.TD_V2_ST['PEER_INDEX_TABLE']:
                 pass
            elif st == mrtparse.TD_V2_ST['RIB_IPV4_UNICAST'] or st == mrtparse.TD_V2_ST['RIB_IPV6_UNICAST']:
                rel_entries += 1
                netstr = "%s/%i" % (data['prefix'], data['prefix_length'])
                try:
                    net = ipaddress.ip_network(netstr, strict=True)
                except ValueError:
                    net = None
                if net is None:
                    raise ValueError("Cannot parse network %s" % netstr)
                if accept_net(net):
                    for ent in data['rib_entries']:
                        ribs += 1
                        as_path = parse_path(ent['path_attributes'])
                        if len(as_path) == 0:
                            print("Skipping empty path for %s" % net)
                        elif valid_asn(as_path[-1], net):
                            merge_path(res, net, as_path)
            elif st == mrtparse.TD_V2_ST['RIB_IPV4_MULTICAST'] or st == mrtparse.TD_V2_ST['RIB_IPV6_MULTICAST']:
                # We can skip multicast subtypes
                pass
            else:
                raise NotImplementedError("Dump subtype %i (%s) is not implemented" % (st, list(data['subtype'].values())[0]))
        elif t == mrtparse.MRT_T['BGP4MP']:
            # We can skip this type
            pass
        else:
            raise NotImplementedError("Dump type %i (%s) is not implemented" % (t, list(data['type'].values())[0]))
        if ribs > rep_ribs + 100000:
            print("... %i/%i entries, %i routes" % (rel_entries, entries, ribs))
            rep_ribs = ribs


RES = {}
for arg in sys.argv[1:]:
    print("Processing %s" % arg)
    process_file(arg, RES)

with open("output.txt", "w") as out:
    for net in sorted(RES, key=net_sorting_key):
        paths = RES[net]
        first = True
        for path, cnt in sorted(paths.values(), key=lambda f: (-f[1], f[0])):
           out.write("%s%s AS%i # %i times %s\n" % ("" if first else "# ", net, path[0], cnt, " ".join("AS%i" % x for x in path)))
           first = False
        out.write("\n")
