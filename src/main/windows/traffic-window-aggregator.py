from collections import defaultdict
import numpy as np
from scapy.all import IP, TCP, UDP, Raw

from features.packet_vectorizer import entropy
from windows.traffic_window_aggregator import processa_vetor

JANELA = 5.0

buckets = defaultdict(lambda: defaultdict(list))

# [0]  total_bytes
# [1]  total_pkts
# [2]  uniq_src_ips
# [3]  uniq_dst_ports
# [4]  avg_pkt_len
# [5]  std_pkt_len
# [6]  avg_ttl
# [7]  proto_major  # 0=ICMP, 6=TCP, 17=UDP, outro=-1
# [8]  tcp_syn_cnt
# [9]  tcp_ack_cnt
# [10] tcp_psh_cnt
# [11] entropy_payload average of packages
# Function that compresses the list of packages into 1 vector:


def pacotes2vetor(pacotes):
    if not pacotes:
        return np.zeros(12)
    bytes_total = sum(len(p) for p in pacotes)
    pkts = len(pacotes)
    src_ips = {p[IP].src for p in pacotes}
    dst_ports = {p.dport if TCP in p or UDP in p else 0 for p in pacotes}
    lens = [len(p) for p in pacotes]
    ttls = [p[IP].ttl for p in pacotes]
    protos = {p[IP].proto for p in pacotes}
    syn = ack = psh = 0
    entropies = []
    for p in pacotes:
        if TCP in p:
            f = int(p[TCP].flags)
            syn += bool(f & 0x02)
            ack += bool(f & 0x10)
            psh += bool(f & 0x08)
        entropies.append(entropy(bytes(p[Raw]) if p.haslayer(Raw) else b""))

    v = np.zeros(12)
    v[0] = bytes_total
    v[1] = pkts
    v[2] = len(src_ips)
    v[3] = len(dst_ports)
    v[4] = np.mean(lens)
    v[5] = np.std(lens)
    v[6] = np.mean(ttls)
    v[7] = next(iter(protos)) if len(protos) == 1 else -1
    v[8] = syn
    v[9] = ack
    v[10] = psh
    v[11] = np.mean(entropies) if entropies else 0
    return v


# Calculate flow key.
# Store packet in bucket[slot][key].
# When the clock exceeds slot + WINDOW, convert that bucket to a vector, send it to the model, then delete it.


def arredonda(ts):
    return int(ts / JANELA) * JANELA


def chave(p):
    ip = p[IP]
    return (ip.proto, ip.src, ip.dst, ip.dport if TCP in p or UDP in p else 0)


def fecha_slot(slot):
    if slot not in buckets:
        return
    for fluxo_key, pacotes in buckets[slot].items():
        vet = pacotes2vetor(pacotes)
        processa_vetor(vet, fluxo_key, slot)
    del buckets[slot]
