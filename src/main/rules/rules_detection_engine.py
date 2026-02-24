import time

from rules.rules_detection_engine import (
    pps,
    bps,
    uniq,
    syn_counter,
    μ_pps,
    σ_pps,
    μ_uniq,
    σ_uniq,
)
from examples.mini_ids import corta
from logs.alert_logger import alerta


def detecta(f):
    ip = f["src"]
    agora = time.time()

    # updates counters
    pps[ip].append((agora, 1))
    bps[ip].append((agora, f["len"]))
    uniq[ip].add(f["dport"])

    # clear sliding window (last 60 seconds)
    corta(pps[ip], agora - 60)
    corta(bps[ip], agora - 60)

    # DDoS test
    if len(pps[ip]) > μ_pps[ip] + 3 * σ_pps[ip]:
        alerta("DDoS", ip)

    # port scan test
    if len(uniq[ip]) > μ_uniq[ip] + 3 * σ_uniq[ip]:
        alerta("PortScan", ip)

    # SYN flood test
    if f["flags"] == "S":
        syn_counter[ip] += 1
    elif "A" in f["flags"]:
        syn_counter[ip] = 0
    if syn_counter[ip] > 100:
        alerta("SYN-Flood", ip)
