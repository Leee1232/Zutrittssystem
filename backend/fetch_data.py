# fetch_data.py
import psycopg2
from config import DATABASE_URL

def fetch_schueler_data():
    try:
        # Verbindung zur Datenbank herstellen
        connection = psycopg2.connect(DATABASE_URL)
        cursor = connection.cursor()

        # Beispiel: Abrufen aller Schüler
        query = "SELECT * FROM schueler;"
        cursor.execute(query)
        rows = cursor.fetchall()

        # Ergebnisse ausgeben
        print("Schülerdaten:")
        for row in rows:
            print(row)

    except Exception as e:
        print("Fehler beim Abrufen der Daten:", e)
    finally:
        if 'connection' in locals() and connection:
            cursor.close()
            connection.close()

if __name__ == "__main__":
    fetch_schueler_data()
