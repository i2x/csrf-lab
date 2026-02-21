const express = require("express");
const path = require("path");

const app = express();
app.use(express.static(path.join(__dirname, "public")));

app.listen(4000, () => {
  console.log("Attacker running on http://localhost:4000");
  console.log("Open: http://localhost:4000/attack.html");
});