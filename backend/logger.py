# logger.py
import logging

# Logger konfigurieren
logger = logging.getLogger("api_logger")
logger.setLevel(logging.INFO)

# Datei-Handler hinzufügen
file_handler = logging.FileHandler("system.log")
file_handler.setLevel(logging.INFO)

# Format des Logs
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)

# Console-Handler hinzufügen
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)

# Handler dem Logger hinzufügen
logger.addHandler(file_handler)
logger.addHandler(console_handler)
