require("dotenv").config();

const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const authMiddleware = require("./middlewares/auth-middleware");

const app = express();

const saltRounds = 10;

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
        return res.json({ data: { token: jwt.sign({ name }, process.env.JWT_SECRET) } });
      }
    }

    res.status(401).json({ errors: ["Not allowed"] });
  } catch (err) {
    res.status(500).json({ errors: [err.toString()] });
    console.log(err);
  }
});

app.get("/records", authMiddleware, (req, res) => {
  res.json(records.filter(record => record.userName === req.user.name));
});

app.listen(3000);
