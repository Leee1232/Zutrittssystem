// server.js
const { Pool } = require('pg');
const config = require('./config');

// Erstelle eine Pool-Verbindung zur PostgreSQL-Datenbank
const pool = new Pool({
  user: config.db.user,
  host: config.db.host,
  database: config.db.database,
  password: config.db.password,
  port: config.db.port,
});

// Teste die Verbindung
pool.connect((err, client, release) => {
  if (err) {
    console.error('Fehler bei der Verbindung zur Datenbank', err);
    return;
  }
  console.log('Erfolgreich mit der PostgreSQL-Datenbank verbunden');
  release();
});

// Beispiel für eine einfache Datenbankabfrage
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Fehler bei der Abfrage', err);
  } else {
    console.log('Abfrageergebnis:', res.rows);
  }
  pool.end();
});
