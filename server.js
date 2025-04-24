require('dotenv').config();
const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

const allowedOrigins = [
  'http://localhost',
  'http://127.0.0.1', 
  'http://localhost:5500',
  'null'
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`⚠️  Intento de acceso desde origen no permitido: ${origin}`);
      callback(new Error('Acceso bloqueado por política CORS'));
    }
  },
  methods: "GET,POST,PUT,DELETE,OPTIONS",
  allowedHeaders: ["Content-Type", "Authorization", "Origin", "X-Requested-With"],
  exposedHeaders: ["Authorization"],
  credentials: true,
  preflightContinue: false,
  optionsSuccessStatus: 204,
  maxAge: 86400
};

app.use(cors(corsOptions));

app.options('*', cors(corsOptions));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Expose-Headers', 'Authorization');
  res.header('X-Powered-By', 'Mi Super Servidor');
  next();
});

app.use(express.json());

// Configuración de la base de datos
const pool = mysql.createPool({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "pfg_aleix",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

app.post("/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ 
                success: false,
                message: "Nombre, email y contraseña son obligatorios" 
            });
        }

        const [existing] = await pool.query("SELECT id FROM users WHERE email = ?", [email]);
        if (existing.length > 0) {
            return res.status(409).json({
                success: false,
                message: "El email ya está registrado"
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const secret = speakeasy.generateSecret({ 
            length: 20,
            name: `MiApp (${email})`,
            issuer: "MiApp"
        });

        const backupCodes = Array.from({length: 5}, () => 
            Math.floor(100000 + Math.random() * 900000).toString()
        );

        const [result] = await pool.query(
            "INSERT INTO users (name, email, password, mfa_secret, backup_codes) VALUES (?, ?, ?, ?, ?)",
            [name, email, hashedPassword, secret.base32, JSON.stringify(backupCodes)]
        );

        const qrCodeDataURL = await qrcode.toDataURL(secret.otpauth_url);

        res.status(201).json({
            success: true,
            qrCodeDataURL,
            backupCodes,
            user: {
                id: result.insertId,
                name,
                email
            }
        });

    } catch (error) {
        console.error("Error en registro:", error);
        res.status(500).json({
            success: false,
            message: "Error en el servidor"
        });
    }
});

app.post("/login-precheck", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "Email y contraseña son requeridos"
            });
        }

        const [users] = await pool.query(
            "SELECT id, name, password FROM users WHERE email = ?",
            [email]
        );

        if (users.length === 0) {
            return res.status(401).json({
                success: false,
                message: "Credenciales inválidas"
            });
        }

        const passwordMatch = await bcrypt.compare(password, users[0].password);
        if (!passwordMatch) {
            return res.status(401).json({
                success: false,
                message: "Credenciales inválidas"
            });
        }

        res.json({
            success: true,
            message: "Procede con MFA",
            user: {
                id: users[0].id,
                name: users[0].name
            }
        });

    } catch (error) {
        console.error("Error en login-precheck:", error);
        res.status(500).json({
            success: false,
            message: "Error en el servidor"
        });
    }
});

app.post("/login", async (req, res) => {
    try {
        const { email, password, token: mfaToken } = req.body;

        if (!email || !password || !mfaToken) {
            return res.status(400).json({
                success: false,
                message: "Todos los campos son obligatorios"
            });
        }

        const [users] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);
        if (users.length === 0) {
            return res.status(401).json({
                success: false,
                message: "Credenciales inválidas"
            });
        }

        const user = users[0];
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({
                success: false,
                message: "Credenciales inválidas"
            });
        }

        const backupCodes = JSON.parse(user.backup_codes || "[]");
        const tokenValid = speakeasy.totp.verify({
            secret: user.mfa_secret,
            encoding: "base32",
            token: mfaToken,
            window: 2
        });

        const isBackupCode = backupCodes.includes(mfaToken);

        if (!tokenValid && !isBackupCode) {
            return res.status(401).json({
                success: false,
                message: "Código MFA inválido"
            });
        }

        if (isBackupCode) {
            const updatedCodes = backupCodes.filter(code => code !== mfaToken);
            await pool.query(
                "UPDATE users SET backup_codes = ? WHERE id = ?",
                [JSON.stringify(updatedCodes), user.id]
            );
        }

        const token = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET || 'tu_secreto_seguro',
            { expiresIn: '1h' }
        );

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email
            }
        });

    } catch (error) {
        console.error("Error en login:", error);
        res.status(500).json({
            success: false,
            message: "Error en el servidor"
        });
    }
});

app.get("/generate-new-qr", async (req, res) => {
    try {
        const { email } = req.query;
        if (!email) {
            return res.status(400).json({
                success: false,
                message: "Email es requerido"
            });
        }

        const newSecret = speakeasy.generateSecret({ 
            length: 20,
            name: `MiApp (${email})`,
            issuer: "MiApp"
        });

        await pool.query(
            "UPDATE users SET mfa_secret = ? WHERE email = ?",
            [newSecret.base32, email]
        );

        const qrCodeDataURL = await qrcode.toDataURL(newSecret.otpauth_url);

        res.json({
            success: true,
            qrCodeDataURL
        });

    } catch (error) {
        console.error("Error generando QR:", error);
        res.status(500).json({
            success: false,
            message: "Error generando nuevo QR"
        });
    }
});

app.get('/cors-test', (req, res) => {
  res.json({ 
    status: 'success',
    message: '¡CORS configurado correctamente!',
    allowedOrigins: allowedOrigins,
    yourOrigin: req.headers.origin || 'No detectado',
    timestamp: new Date().toISOString()
  });
});

app.use((err, req, res, next) => {
  if (err.message === 'Acceso bloqueado por política CORS') {
    return res.status(403).json({
      success: false,
      message: "Acceso no autorizado desde tu dominio"
    });
  }
  next(err);
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`\n🚀 Servidor activo en http://localhost:${PORT}`);
    console.log("🔧 Configuración CORS habilitada para:");
    allowedOrigins.forEach(origin => console.log(`   → ${origin}`));
});
