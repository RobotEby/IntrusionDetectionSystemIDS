import time


def alerta(tipo, ip):
    with open("alerts.log", "a") as log:
        log.write(f"{time.time()} {tipo} {ip}\n")
