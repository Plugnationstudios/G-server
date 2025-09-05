const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(helmet());
app.use(morgan("dev"));
app.use(express.json());

// Base route
app.get("/", (req, res) => {
  res.json({ message: "🚀 God Mode Server is alive." });
});

// Start server
app.listen(PORT, () => {
  console.log(`⚡ Server running at http://localhost:${PORT}`);
});
