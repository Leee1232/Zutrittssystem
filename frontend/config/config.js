// config.js

module.exports = {
  // Datenbankverbindung
  db: {
    user: "zutrittssystemdb_user", // Benutzername für die Datenbank
    host: "dpg-ct6tiapopnds73dj0i4g-a.oregon-postgres.render.com", // Datenbankhost (für lokale Entwicklung 'localhost')
    database: "zutrittssystemdb", // Name der zu verwendenden Datenbank
    password: "M0C5SyNtuefBsl3Tm0rGZ2Bps6zeawRl", // Passwort für den Datenbankbenutzer
    port: 5432, // PostgreSQL-Standardport
    ssl: { rejectUnauthorized: false }, // SSL für externe Verbindungen
  },

  // Serverkonfiguration
  server: {
    host: "localhost", // Host für den Server
    port: 3000, // Port, auf dem der Server läuft
    environment: "development", // Umgebung (development, production, etc.)
    apiPrefix: "/api", // API-Präfix für alle Endpunkte
  },

  // CORS-Konfiguration (für die API)
  cors: {
    allowedOrigins: ["http://localhost:3000"], // Erlaubte Ursprünge (z.B. Frontend-URL)
    methods: ["GET", "POST", "PUT", "DELETE"], // Erlaubte HTTP-Methoden
    allowedHeaders: ["Content-Type", "Authorization"], // Erlaubte Header
  },
};
