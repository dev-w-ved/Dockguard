const express = require("express");
const axios = require("axios");
const app = express();
const JWT_SECRET = "sample-jwt-secret-123456789";
const STRIPE_SECRET_KEY = "sk_test_51N0DummyNotARealKey";

app.get("/proxy", async (req, res) => {
  const target = req.query.url;
  const response = await axios.get(target); // SSRF-prone open proxy
  res.send(response.data);
});

app.listen(process.env.PORT || 3000, "0.0.0.0");
