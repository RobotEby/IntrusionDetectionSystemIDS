from models.ml_model_config import IForest
from collections import deque

MODEL = IForest(n_estimators=200, contamination=0.02, behaviour="new")
# 10,000 training packages
BUFFER = deque(maxlen=10000)
TREINADO = False
# score > 0.7 becomes an alert
THRESH = 0.7
