const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const SQLiteStore = require("connect-sqlite3")(session);
const csrf = require("csurf");
const path = require("path");
const bodyParser = require("body-parser");

const app = express();
const PORT = 3000;

// Database setup
const db = new sqlite3.Database("./app.db", (err) => {
    if (err) console.error(err);
    console.log("Connected to SQLite database");
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        content TEXT,
        completed INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

// Middleware
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.urlencoded({ extended: false }));

app.use(session({
    store: new SQLiteStore(),
    secret: "supersecretkey",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 60 * 60 * 1000 }
}));

const csrfProtection = csrf();
app.use(csrfProtection);

// Auth check middleware
function requireLogin(req, res, next) {
    if (!req.session.userId) return res.redirect("/login");
    next();
}

// Routes
app.get("/", (req, res) => res.redirect("/login"));

app.get("/login", (req, res) => {
    res.render("login", { csrfToken: req.csrfToken(), error: null });
});

app.post("/login", (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
        if (user && bcrypt.compareSync(password, user.password)) {
            req.session.userId = user.id;
            req.session.username = user.username;
            return res.redirect("/dashboard");
        }
        res.render("login", { csrfToken: req.csrfToken(), error: "Invalid username or password" });
    });
});

app.get("/register", (req, res) => {
    res.render("register", { csrfToken: req.csrfToken(), error: null });
});

app.post("/register", (req, res) => {
    const { username, password, confirmPassword } = req.body;
    if (password !== confirmPassword) {
        return res.render("register", { csrfToken: req.csrfToken(), error: "Passwords do not match" });
    }
    const hashed = bcrypt.hashSync(password, 10);
    db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashed], function (err) {
        if (err) {
            return res.render("register", { csrfToken: req.csrfToken(), error: "Username already exists" });
        }
        res.redirect("/login");
    });
});

app.get("/logout", (req, res) => {
    req.session.destroy(() => res.redirect("/login"));
});

app.get("/dashboard", requireLogin, (req, res) => {
    db.all(`SELECT * FROM tasks WHERE user_id = ?`, [req.session.userId], (err, tasks) => {
        const total = tasks.length;
        const completed = tasks.filter(t => t.completed).length;
        const pending = total - completed;
        res.render("dashboard", { username: req.session.username, total, completed, pending });
    });
});

app.get("/todo", requireLogin, (req, res) => {
    db.all(`SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC`, [req.session.userId], (err, tasks) => {
        res.render("todo", { username: req.session.username, tasks, csrfToken: req.csrfToken() });
    });
});

app.post("/todo", requireLogin, (req, res) => {
    const { content } = req.body;
    db.run(`INSERT INTO tasks (user_id, content) VALUES (?, ?)`, [req.session.userId, content], () => {
        res.redirect("/todo");
    });
});

app.post("/task/:id/toggle", requireLogin, (req, res) => {
    db.get(`SELECT completed FROM tasks WHERE id = ? AND user_id = ?`, [req.params.id, req.session.userId], (err, task) => {
        if (!task) return res.redirect("/todo");
        db.run(`UPDATE tasks SET completed = ? WHERE id = ?`, [task.completed ? 0 : 1, req.params.id], () => {
            res.redirect("/todo");
        });
    });
});

app.post("/task/:id/delete", requireLogin, (req, res) => {
    db.run(`DELETE FROM tasks WHERE id = ? AND user_id = ?`, [req.params.id, req.session.userId], () => {
        res.redirect("/todo");
    });
});

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
