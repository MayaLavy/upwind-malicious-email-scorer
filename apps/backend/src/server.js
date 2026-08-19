require("dotenv").config();

const express = require("express");
const healthRouter = require("./routes/health");
const analyzeRouter = require("./routes/analyze");

const app = express();
const port = Number(process.env.PORT) || 3000;

app.use(express.json({ limit: "256kb" }));

app.use("/health", healthRouter);
app.use("/analyze", analyzeRouter);

app.use((_req, res) => {
  res.status(404).json({ error: "Not found" });
});

app.listen(port, () => {
  console.log(`Backend listening on http://localhost:${port}`);
});
