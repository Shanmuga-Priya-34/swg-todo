const express = require("express");
require("dotenv").config();

const nodemailer = require("nodemailer");
const session = require("express-session");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const SQLiteStore = require("connect-sqlite3")(session);
const csrf = require("csurf");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");
const speakeasy = require("speakeasy");
const path = require("path");
const bodyParser = require("body-parser");

const app = express();

app.set("trust proxy", 1);

const PORT = 3000;

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const db = new sqlite3.Database("./app.db", (err) => {

    if (err) {
        console.log("There is a small error in database connection.");
        console.error("Database connection error:", err.message);
    } else {
        console.log("Connected to SQLite database");
    }

});

db.serialize(() => {

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        email TEXT,
        role TEXT DEFAULT 'user',
        totp_secret TEXT,
        twofa_enabled INTEGER DEFAULT 1
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        content TEXT,
        completed INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT,
        ip TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

});

function addLog(username, action, ip) {

    db.run(
        `INSERT INTO logs (username, action, ip)
         VALUES (?, ?, ?)`,
        [username, action, ip]
    );

}

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],

                scriptSrc: [
                    "'self'",
                    "'unsafe-inline'",
                    "https://cdn.jsdelivr.net"
                ],

                styleSrc: [
                    "'self'",
                    "'unsafe-inline'"
                ],

                imgSrc: [
                    "'self'",
                    "data:"
                ]
            }
        }
    })
);

app.use(session({

    store: new SQLiteStore({
        db: "sessions.db",
        dir: "./"
    }),

    secret: process.env.SESSION_SECRET || "CHANGE_THIS_SECRET",

    resave: false,

    saveUninitialized: false,

    cookie: {
        httpOnly: true,
        secure: false,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60
    }

}));

const csrfProtection = csrf();

app.use(csrfProtection);

const loginLimiter = rateLimit({

    windowMs: 15 * 60 * 1000,
    max: 100,
    message: "Too many login attempts. Please try again later."

});

app.use("/login", loginLimiter);

function requireLogin(req, res, next) {

    if (!req.session.userId) {
        return res.redirect("/login");
    }

    next();

}

function requireAdmin(req, res, next) {

    if (req.session.role !== "admin") {

        addLog(
            req.session.username,
            "Unauthorized Admin Access Attempt",
            req.ip
        );

        return res.status(403).send("Access Denied");

    }

    next();

}

app.get("/", (req, res) => {
    res.redirect("/login");
});

app.get("/login", (req, res) => {

    res.render("login", {
        csrfToken: req.csrfToken(),
        error: null
    });

});

app.post("/login",

    [
        body("username").trim().escape(),
        body("password").trim()
    ],

    (req, res) => {

        const errors = validationResult(req);

        if (!errors.isEmpty()) {

            addLog("Unknown", "Invalid Login Input", req.ip);

            return res.render("login", {
                csrfToken: req.csrfToken(),
                error: "Invalid input"
            });

        }

        const { username, password } = req.body;

        db.get(
            `SELECT * FROM users WHERE username = ?`,
            [username],

            async (err, user) => {

                if (err) {

                    addLog(username, "Login Server Error", req.ip);

                    return res.render("login", {
                        csrfToken: req.csrfToken(),
                        error: "Server error"
                    });

                }

                if (user && bcrypt.compareSync(password, user.password)) {

                    const currentOtp = speakeasy.totp({
                        secret: user.totp_secret,
                        encoding: "base32",
                        digits: 4
                    });

                    req.session.tempUser = {
                        id: user.id,
                        username: user.username,
                        role: user.role,
                        secret: user.totp_secret,
                        email: user.email,
                        otp: currentOtp
                    };

                    try {

                        await transporter.sendMail({
                            from: process.env.EMAIL_USER,
                            to: user.email,
                            subject: "Your OTP Code",
                            text: `Your OTP is ${currentOtp}`
                        });

                        addLog(
                            username,
                            "OTP Sent Successfully",
                            req.ip
                        );

                    } catch (emailError) {

                        console.error(emailError);

                        addLog(
                            username,
                            "OTP Email Failed",
                            req.ip
                        );

                        return res.send("Failed to send OTP");

                    }

                    addLog(
                        username,
                        "Password Verification Success",
                        req.ip
                    );

                    return res.redirect("/verify-otp");

                }

                addLog(username, "Login Failed", req.ip);

                res.render("login", {
                    csrfToken: req.csrfToken(),
                    error: "Invalid username or password"
                });

            }

        );

    }

);

app.get("/verify-otp", (req, res) => {

    if (!req.session.tempUser) {
        return res.redirect("/login");
    }

    res.render("verify-otp", {
        csrfToken: req.csrfToken(),
        error: null
    });

});

app.post("/verify-otp", (req, res) => {

    if (!req.session.tempUser) {
        return res.redirect("/login");
    }

    const { otp } = req.body;

    if (otp !== req.session.tempUser.otp) {

        addLog(
            req.session.tempUser.username,
            "Invalid OTP Attempt",
            req.ip
        );

        return res.render("verify-otp", {
            csrfToken: req.csrfToken(),
            error: "Invalid OTP"
        });

    }

    req.session.userId = req.session.tempUser.id;
    req.session.username = req.session.tempUser.username;
    req.session.role = req.session.tempUser.role;

    addLog(
        req.session.username,
        "MFA Verification Success",
        req.ip
    );

    delete req.session.tempUser;

    res.redirect("/dashboard");

});

app.get("/register", (req, res) => {

    res.render("register", {
        csrfToken: req.csrfToken(),
        error: null
    });

});

app.post("/register",

    [
        body("username")
            .trim()
            .isLength({ min: 3 })
            .escape(),

        body("password")
            .isLength({ min: 6 }),

        body("email")
            .isEmail()
            .normalizeEmail()
    ],

    (req, res) => {

        const errors = validationResult(req);

        if (!errors.isEmpty()) {

            addLog(
                "Unknown",
                "Weak Registration Attempt",
                req.ip
            );

            return res.render("register", {
                csrfToken: req.csrfToken(),
                error: "Invalid registration details"
            });

        }

        const {
            username,
            password,
            confirmPassword,
            email
        } = req.body;

        if (password !== confirmPassword) {

            addLog(
                username,
                "Password Mismatch During Registration",
                req.ip
            );

            return res.render("register", {
                csrfToken: req.csrfToken(),
                error: "Passwords do not match"
            });

        }

        const hashed = bcrypt.hashSync(password, 10);

        const secret = speakeasy.generateSecret({
            length: 20
        });

        db.run(
            `INSERT INTO users
            (username, password, email, role, totp_secret, twofa_enabled)
            VALUES (?, ?, ?, ?, ?, ?)`,
            [
                username,
                hashed,
                email,
                "user",
                secret.base32,
                1
            ],

            function (err) {

                if (err) {

                    addLog(
                        username,
                        "Registration Failed - Username Exists",
                        req.ip
                    );

                    return res.render("register", {
                        csrfToken: req.csrfToken(),
                        error: "Username already exists"
                    });

                }

                addLog(
                    username,
                    "User Registered",
                    req.ip
                );

                res.redirect("/login");

            }

        );

    }

);

app.get("/logout", (req, res) => {

    addLog(
        req.session.username,
        "User Logout",
        req.ip
    );

    req.session.destroy(() => {

        res.clearCookie("connect.sid");

        res.redirect("/login");

    });

});

app.get("/dashboard",

    requireLogin,

    (req, res) => {

        db.all(
            `SELECT * FROM tasks WHERE user_id = ?`,
            [req.session.userId],

            (err, tasks) => {

                const total = tasks.length;

                const completed =
                    tasks.filter(t => t.completed).length;

                const pending = total - completed;

                res.render("dashboard", {
                    username: req.session.username,
                    total,
                    completed,
                    pending,
                    role: req.session.role
                });

            }

        );

    }

);

app.get("/todo",

    requireLogin,

    (req, res) => {

        db.all(
            `SELECT * FROM tasks
             WHERE user_id = ?
             ORDER BY created_at DESC`,
            [req.session.userId],

            (err, tasks) => {

                res.render("todo", {
                    username: req.session.username,
                    tasks,
                    csrfToken: req.csrfToken()
                });

            }

        );

    }

);

app.post("/todo",

    requireLogin,

    [
        body("content")
            .trim()
            .isLength({ min: 1, max: 200 })
            .escape()
    ],

    (req, res) => {

        const errors = validationResult(req);

        if (!errors.isEmpty()) {

            addLog(
                req.session.username,
                "Invalid Task Input",
                req.ip
            );

            return res.redirect("/todo");

        }

        const { content } = req.body;

        db.run(
            `INSERT INTO tasks
             (user_id, content)
             VALUES (?, ?)`,
            [req.session.userId, content],

            () => {

                addLog(
                    req.session.username,
                    `Created Task: ${content}`,
                    req.ip
                );

                res.redirect("/todo");

            }

        );

    }

);

app.post("/task/:id/toggle",

    requireLogin,

    (req, res) => {

        db.get(
            `SELECT completed
             FROM tasks
             WHERE id = ?
             AND user_id = ?`,
            [req.params.id, req.session.userId],

            (err, task) => {

                if (!task) {

                    addLog(
                        req.session.username,
                        `Unauthorized Toggle Attempt: ${req.params.id}`,
                        req.ip
                    );

                    return res.redirect("/todo");

                }

                db.run(
                    `UPDATE tasks
                     SET completed = ?
                     WHERE id = ?`,
                    [task.completed ? 0 : 1, req.params.id],

                    () => {

                        addLog(
                            req.session.username,
                            `Toggled Task ID: ${req.params.id}`,
                            req.ip
                        );

                        res.redirect("/todo");

                    }

                );

            }

        );

    }

);

app.post("/task/:id/delete",

    requireLogin,

    (req, res) => {

        db.run(
            `DELETE FROM tasks
             WHERE id = ?
             AND user_id = ?`,
            [req.params.id, req.session.userId],

            () => {

                addLog(
                    req.session.username,
                    `Deleted Task ID: ${req.params.id}`,
                    req.ip
                );

                res.redirect("/todo");

            }

        );

    }

);

app.get("/admin",

    requireLogin,
    requireAdmin,

    (req, res) => {

        db.all(
            `SELECT * FROM users`,
            [],

            (err, users) => {

                if (err) {
                    return res.send("Error loading users");
                }

                db.all(
                    `SELECT * FROM logs
                     ORDER BY timestamp DESC
                     LIMIT 100`,
                    [],

                    (err, logs) => {

                        if (err) {
                            return res.send("Error loading logs");
                        }

                        const otpFailures = logs.filter(log =>
                            log.action.includes("Invalid OTP")
                        ).length;

                        const failedLogins = logs.filter(log =>
                            log.action.includes("Login Failed")
                        ).length;

                        const successfulLogins = logs.filter(log =>
                            log.action.includes("MFA Verification Success")
                        ).length;

                        const totalUsers = users.length;

                        const totalAdmins = users.filter(
                            user => user.role === "admin"
                        ).length;

                        const totalTasks = logs.filter(log =>
                            log.action.includes("Created Task")
                        ).length;

                        const completedTasks = logs.filter(log =>
                            log.action.includes("Toggled Task ID")
                        ).length;

                        const pendingTasks =
                            totalTasks - completedTasks;

                        const unauthorizedAttempts = logs.filter(log =>
                            log.action.includes("Unauthorized")
                        ).length;

                        // -----------------------------
                        // ANOMALY DETECTION
                        // -----------------------------

                        const suspiciousFailedLogins = logs.filter(log =>
                            log.action.includes("Login Failed")
                        ).length;

                        const suspiciousOtpFailures = logs.filter(log =>
                            log.action.includes("Invalid OTP")
                        ).length;

                        const suspiciousUsers = logs.filter(log =>
                            log.action.includes("Login Failed") ||
                            log.action.includes("Invalid OTP")
                        );

                        res.render("admin", {

                            username: req.session.username,

                            users,
                            logs,

                            otpFailures,
                            failedLogins,
                            successfulLogins,

                            totalUsers,
                            totalAdmins,

                            totalTasks,
                            completedTasks,
                            pendingTasks,

                            unauthorizedAttempts,

                            suspiciousFailedLogins,
                            suspiciousOtpFailures,
                            suspiciousUsers

                        });

                    }

                );

            }

        );

    }

);
app.use((err, req, res, next) => {

    console.error(err.stack);

    addLog(
        req.session?.username || "Unknown",
        "Application Error",
        req.ip
    );

    res.status(500).send("Something went wrong!");

});

app.listen(PORT, () => {

    console.log(`Server running at http://localhost:${PORT}`);

});