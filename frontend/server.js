const express = require("express");
const { Pool } = require("pg");
const dbConfig = require("./config/config"); // Importiere die Konfigurationsdatei

const app = express();
const port = 3000;

// PostgreSQL-Pool
const pool = new Pool({
  user: dbConfig.db.user,
  host: dbConfig.db.host,
  database: dbConfig.db.database,
  password: dbConfig.db.password,
  port: dbConfig.db.port,
  ssl: { rejectUnauthorized: false },
});

// Middleware
app.use(express.json());

// API-Endpoints

// 1. Alle Schüler abfragen
app.get("/api/schueler", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM schueler");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send("Fehler beim Abrufen der Schülerdaten");
  }
});

// 2. Einen Schüler hinzufügen
app.post("/api/schueler", async (req, res) => {
  const { vorname, nachname, klasse, rfid_tag } = req.body;
  try {
    const result = await pool.query(
      "INSERT INTO schueler (vorname, nachname, klasse, rfid_tag) VALUES ($1, $2, $3, $4) RETURNING *",
      [vorname, nachname, klasse, rfid_tag]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send("Fehler beim Hinzufügen des Schülers");
  }
});

// 3. Räume abfragen
app.get("/api/raeume", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM raeume");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send("Fehler beim Abrufen der Räume");
  }
});

// 4. Berechtigungen eines Schülers abfragen
app.get("/api/berechtigungen/:schuelerId", async (req, res) => {
  const { schuelerId } = req.params;
  try {
    const result = await pool.query(
      "SELECT * FROM berechtigungen WHERE schueler_id = $1",
      [schuelerId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send("Fehler beim Abrufen der Berechtigungen");
  }
});

// Server starten
app.listen(port, () => {
  console.log(`Server läuft auf http://localhost:${port}`);
});
