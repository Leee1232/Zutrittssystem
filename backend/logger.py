# logger.py
import logging
from logging.handlers import RotatingFileHandler
import os

# Log-Verzeichnis erstellen, falls es nicht existiert
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Logger konfigurieren
logger = logging.getLogger("api_logger")
logger.setLevel(logging.DEBUG)  # Setze das Logging-Level auf DEBUG für detailliertere Informationen

# Datei-Handler hinzufügen (mit RotatingFileHandler)
file_handler = RotatingFileHandler(
    os.path.join(log_dir, "system.log"), 
    maxBytes=5_000_000,  # 5 MB maximale Größe pro Datei
    backupCount=5        # Maximal 5 Backup-Dateien behalten
)
file_handler.setLevel(logging.DEBUG)

# Console-Handler hinzufügen
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# Format des Logs
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Handler dem Logger hinzufügen
if not logger.handlers:  # Verhindere doppelte Handler
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

# Testlog, um sicherzustellen, dass alles funktioniert
logger.debug("Logger initialized successfully.")
