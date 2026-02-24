from collections import defaultdict, deque

baseline = {
    # packets per second
    "pps": defaultdict(deque),
    # bytes per second
    "bps": defaultdict(deque),
    # single ports
    "uniq": defaultdict(set),
}
# learning seconds
janela = 60
