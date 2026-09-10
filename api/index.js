import express from "express";
import helmet from "helmet";
import cors from "cors";
import { rateLimit } from "express-rate-limit";

import revanstoreV2 from "./revanstoreV2.js";
import register from "./register.js";
import resetPassword from "./reset-pw.js";
import topupbussid from "./topupbussid.js";

const app = express();

app.disable("x-powered-by");
app.set("trust proxy", 1);

const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map(v => v.trim())
  .filter(Boolean);

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
  })
);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Origin not allowed"));
    },
    credentials: true,
    methods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "X-Requested-With"]
  })
);

app.use(express.json({
  limit: "100kb",
  strict: true
}));

app.use(express.urlencoded({
  extended: false,
  limit: "20kb"
}));

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 100,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    error: "Too many requests"
  }
});

const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    error: "Too many authentication requests"
  }
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    error: "Too many registration requests"
  }
});

const resetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    error: "Too many password reset requests"
  }
});

app.use("/api", apiLimiter);

function handler(fn) {
  return async (req, res, next) => {
    try {
      await fn(req, res);
    } catch (err) {
      next(err);
    }
  };
}

app.all(
  "/api/revanstoreV2",
  authLimiter,
  handler(revanstoreV2)
);

app.all(
  "/api/register",
  registerLimiter,
  handler(register)
);

app.all(
  "/api/reset-pw",
  resetLimiter,
  handler(resetPassword)
);

app.all(
  "/api/topupbussid",
  handler(topupbussid)
);

app.get("/api/health", (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({ ok: true });
});

app.use("/api", (req, res) => {
  res.status(404).json({
    error: "API endpoint not found"
  });
});

app.use((err, req, res, next) => {
  console.error(err?.message || err);

  if (!res.headersSent) {
    res.status(500).json({
      error: "Internal server error"
    });
  }
});

export default app;