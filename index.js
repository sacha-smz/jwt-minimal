require("dotenv").config();

const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const authMiddleware = require("./middlewares/auth-middleware");

const app = express();

const saltRounds = 10;

// stockage dans des arrays pour la démo, vs. BDD ou Redis en conditions réelles
const refreshTokens = [];
const users = [];
const records = [
  {
    userName: "zouzou",
    translation: "Hola chicos"
  },
  {
    userName: "bloublou",
    translation: "Gut geschlafen ?"
  }
];

app.use(express.urlencoded({ extended: true }), express.json());

app.get("/users", (_, res) => {
  res.json(
    users.map(user => ({
      name: user.name
    }))
  );
});

app.post("/users", async (req, res) => {
  try {
    const { name, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    users.push({ name, password: hashedPassword });
    res.status(201).json({ data: { success: true } });
  } catch (err) {
    res.status(500).json({ errors: [err.toString()] });
    console.log(err);
  }
});

app.post("/users/login", async (req, res) => {
  try {
    const { name, password } = req.body;

    for (const user of users) {
      if (user.name === name && (await bcrypt.compare(password, user.password))) {
        // 40 secondes pour la démo, 10-15 min en conditions réelles
        const token = jwt.sign({ name }, process.env.JWT_SECRET, { expiresIn: "40s" });

        const refreshToken = jwt.sign({ name }, process.env.REFRESH_SECRET);
        refreshTokens.push(refreshToken);

        return res.json({ data: { token, refreshToken } });
      }
    }

    res.status(401).json({ errors: ["Not allowed"] });
  } catch (err) {
    res.status(500).json({ errors: [err.toString()] });
    console.log(err);
  }
});

app.post("/refresh-token", (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) return res.status(401).json({ errors: ["Missing token"] });

  if (!refreshTokens.includes(refreshToken)) return res.status(403).json({ errors: ["Invalid token"] });

  jwt.verify(refreshToken, process.env.REFRESH_SECRET, (err, user) => {
    if (err) return res.status(403).json({ errors: ["Invalid token"] });

    const token = jwt.sign({ name: user.name }, process.env.JWT_SECRET, { expiresIn: "40s" });
    res.json({ data: { token } });
  });
});

app.post("/logout", (req, res) => {
  const refreshTokenIndex = refreshTokens.indexOf(req.body.refreshToken);
  if (refreshTokenIndex > -1) {
    refreshTokens.splice(refreshTokenIndex, 1);
  }
  res.json({ data: { success: true } });
});

app.get("/records", authMiddleware, (req, res) => {
  res.json(records.filter(record => record.userName === req.user.name));
});

app.listen(3000);
