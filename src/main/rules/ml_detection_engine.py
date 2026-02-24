from scapy.all import sniff, IP
import time
import numpy as np

from models.ml_model_config import MODEL, BUFFER, TREINADO, THRESH
from features.packet_vectorizer import to_vector


def treina():
    global TREINADO
    if len(BUFFER) < 1000:
        return
    X = np.vstack(list(BUFFER))
    MODEL.fit(X)
    TREINADO = True
    print("[+] Modelo treinado com", len(BUFFER), "amostras")


def processa(p):
    if IP not in p:
        return
    v = to_vector(p)
    BUFFER.append(v)
    if not TREINADO:
        if len(BUFFER) % 1000 == 0:
            print("[+] Coletado", len(BUFFER))
            # upper limit
        if len(BUFFER) == 10000:
            treina()
        return
    score = MODEL.decision_function(v.reshape(1, -1))[0]
    if score > THRESH:
        alerta("Anomalia ML", p[IP].src, score)


def alerta(tipo, ip, score):
    t = time.strftime("%F %T")
    msg = f"[{t}] {tipo} ip={ip} score={score:.2f}"
    print(msg)
    with open("ml_alerts.log", "a") as f:
        f.write(msg + "\n")


print("Capturando... (primeiros 10 000 pacotes = treino)")
sniff(prn=processa, store=False, filter="ip")
