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
