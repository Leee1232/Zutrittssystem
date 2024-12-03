// config.js

module.exports = {
  // Datenbankverbindung
  db: {
    user: "deinBenutzername", // Benutzername für die Datenbank
    host: "localhost", // Datenbankhost (für lokale Entwicklung 'localhost')
    database: "deineDatenbankName", // Name der zu verwendenden Datenbank
    password: "deinPasswort", // Passwort für den Datenbankbenutzer
    port: 5432, // PostgreSQL-Standardport
    ssl: false, // SSL-Verbindung (meistens false in der lokalen Entwicklung)
  },

  // Serverkonfiguration
  server: {
    host: "localhost", // Host für den Server
    port: 3000, // Port, auf dem der Server läuft
    environment: "development", // Umgebung (development, production, etc.)
    apiPrefix: "/api", // API-Präfix für alle Endpunkte
  },

  // JWT Authentifizierung (Beispiel für Token-basierte Authentifizierung)
  jwt: {
    secret: "deinGeheimerSchlüssel", // Geheimschlüssel für JWT-Token
    expiration: "1h", // Gültigkeitsdauer des Tokens (1 Stunde)
  },

  // E-Mail Konfiguration (z.B. für SMTP-Server)
  email: {
    service: "gmail", // E-Mail-Dienst (z.B. Gmail)
    user: "deineEmail@gmail.com", // Deine E-Mail-Adresse
    password: "deinEmailPasswort", // Dein E-Mail-Passwort
    from: "no-reply@deineDomain.com", // Absender-E-Mail-Adresse
  },

  // Logging-Konfiguration (z.B. für die Verwendung von winston oder morgan)
  logging: {
    level: "info", // Logging-Level (info, warn, error, debug)
    logToFile: true, // Ob Logs auch in eine Datei geschrieben werden sollen
    logFilePath: "./logs/app.log", // Pfad zur Logdatei
  },

  // CORS-Konfiguration (für die API)
  cors: {
    allowedOrigins: ["http://localhost:3000"], // Erlaubte Ursprünge (z.B. Frontend-URL)
    methods: ["GET", "POST", "PUT", "DELETE"], // Erlaubte HTTP-Methoden
    allowedHeaders: ["Content-Type", "Authorization"], // Erlaubte Header
  },

  // Weitere benutzerdefinierte Konfigurationen:
  custom: {
    appName: "Meine Webanwendung", // Name der Anwendung
    version: "1.0.0", // Version der Anwendung
    supportEmail: "support@deineDomain.com", // Support-E-Mail-Adresse
  },
};
