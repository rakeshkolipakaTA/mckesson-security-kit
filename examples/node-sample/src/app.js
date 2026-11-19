const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const app = express();

const JWT_SECRET = "super-secret-signing-key";                         // hardcoded secret
const NPM_TOKEN = "npm_a8Kx2mQz7RvT4pLw9NcB3yHd6JfE1sUg5VoX";          // fake token

app.get("/run", (req, res) => {
  exec("ls " + req.query.dir, (e, out) => res.send(out));              // command injection
});
app.get("/calc", (req, res) => {
  res.send(String(eval(req.query.expr)));                              // eval of user input
});
app.get("/file", (req, res) => {
  res.send(fs.readFileSync("./data/" + req.query.name, "utf8"));       // path traversal
});
app.get("/hello", (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>");                   // reflected XSS
});
app.get("/re", (req, res) => {
  const re = new RegExp(req.query.pattern);                            // ReDoS / injection
  res.send(String(re.test("aaaaaaaaaaaaaaaaaaaaaaaa")));
});
module.exports = app;
