import express from "express";
import { createServer } from "http";
import cors from "cors";
import path from "path";
import fs from "fs";
import { config } from "dotenv";
import { fileURLToPath } from "url";
import { dirname } from "path";
import { connectDB } from "./config/db.js";
import { socketHandler } from "./socket/index.js";
import { clerkClient } from "@clerk/clerk-sdk-node";
import socialFeedRoutes from "./routes/socialfeed.routes.js";

// ---- Load .env from the same folder as server.js ----
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
config({ path: `${__dirname}/.env` });
// -----------------------------------------------------

const app = express();
const httpServer = createServer(app);

// ---------- CORS (updated) ----------
const allowed = (process.env.ALLOWED_ORIGINS || process.env.FRONTEND_URL || "")
  .split(",")
  .map((s) => s.trim().replace(/\/$/, "")) // strip trailing slash
  .filter(Boolean);

app.set("trust proxy", 1);

app.use(cors({
  origin(origin, cb) {
    // allow same-origin requests (no Origin header), health checks, curl, etc.
    if (!origin) return cb(null, true);
    const o = origin.replace(/\/$/, "");
    if (allowed.includes(o)) return cb(null, true);
    return cb(new Error("CORS not allowed: " + origin), false);
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
}));

// Preflight for all routes
app.options("*", cors());
// -----------------------------------

// Body parsing
app.use(express.json());

// Serve static files from the temp directory
app.use(
  "/temp",
  express.static(path.join(__dirname, "temp"), {
    setHeaders: (res, _path) => {
      res.set("Content-Type", "application/pdf");
      res.set("Content-Disposition", "attachment");
    },
  })
);

// Create temp directory if it doesn't exist
const tempDir = path.join(__dirname, "temp");
if (!fs.existsSync(tempDir)) {
  fs.mkdirSync(tempDir);
}

// Initialize Server
const initializeServer = async () => {
  try {
    await connectDB();
    console.log("Database connection established successfully");

    // Routes
    app.use("/api/socialfeed", socialFeedRoutes);

    app.get("/", (req, res) => {
      res.send("API is running");
    });

    app.get("/health", (req, res) => {
      res.json({
        status: "ok",
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || "development",
      });
    });

    app.post("/api/update-role", async (req, res) => {
      try {
        const { userId, companyId, role } = req.body;
        console.log(userId, companyId, role);

        if (!userId) {
          return res.status(400).json({ error: "User ID is required" });
        }

        const updatedUser = await clerkClient.users.updateUserMetadata(userId, {
          publicMetadata: {
            companyId,
            role,
          },
        });

        res.json({ message: "User metadata updated", user: updatedUser });
      } catch (error) {
        console.error("Error updating user:", error);
        res.status(500).json({ error: "Failed to update user metadata" });
      }
    });

    // Socket setup
    socketHandler(httpServer);

    // Server listen
    const PORT = process.env.PORT || 5000;
    httpServer.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`Environment: ${process.env.NODE_ENV || "development"}`);
      if (allowed.length) {
        console.log("Allowed CORS origins:", allowed);
      } else {
        console.log("No CORS origins configured (ALL same-origin only). Set ALLOWED_ORIGINS or FRONTEND_URL.");
      }
    });
  } catch (error) {
    console.error("Failed to initialize server:", error);
    process.exit(1);
  }
};

initializeServer();
