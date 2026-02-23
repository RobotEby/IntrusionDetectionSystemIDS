#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict, deque
import time, os, statistics

WINDOW = 60
THRESHOLD = 3
SYN_MAX = 100

baseline_pps = defaultdict(deque)
baseline_bps = defaultdict(deque)
baseline_uniq = defaultdict(set)
syn_counter = defaultdict(int)
learn_mode = True
start = time.time()


def corta(dq, limite):
    while dq and dq[0][0] < limite:
        dq.popleft()


def calc_stats(dq):
    vals = [v for _, v in dq]
    return statistics.mean(vals), statistics.stdev(vals) if len(vals) > 1 else (0, 0)


def alerta(tipo, ip):
    t = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[ALERTA] {t} {tipo} origem={ip}")
    with open("alerts.log", "a") as f:
        f.write(f"{time.time()} {tipo} {ip}\n")
