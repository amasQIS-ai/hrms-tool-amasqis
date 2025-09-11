import express from "express";
import { createServer } from "http";
import cors from "cors";
import path from "path";
import fs from "fs";
import { config } from "dotenv";
import { connectDB } from "./config/db.js";
import { socketHandler } from "./socket/index.js"; // we'll pass CORS options into this
import { fileURLToPath } from "url";
import { dirname } from "path";
import { clerkClient } from "@clerk/clerk-sdk-node";
import socialFeedRoutes from "./routes/socialfeed.routes.js";

config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const httpServer = createServer(app);

// ---------- CORS CONFIG (HTTP) ----------
const allowed = (process.env.ALLOWED_ORIGINS || process.env.FRONTEND_URL || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

app.set("trust proxy", 1); // behind nginx

app.use(cors({
  origin(origin, cb) {
    // allow no-origin (curl, health checks) and same-origin
    if (!origin) return cb(null, true);
    if (allowed.includes(origin)) return cb(null, true);
    return cb(new Error("CORS not allowed: " + origin), false);
  },
  credentials: true,
  methods: ["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization","X-Requested-With"]
}));

// Preflight
app.options("*", cors());

// ---------- JSON + static files ----------
app.use(express.json());

// Serve static files from the temp directory
app.use(
  "/temp",
  express.static(path.join(__dirname, "temp"), {
    setHeaders: (res) => {
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

// ---------- INIT ----------
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
        if (!userId) return res.status(400).json({ error: "User ID is required" });

        const updatedUser = await clerkClient.users.updateUserMetadata(userId, {
          publicMetadata: { companyId, role },
        });

        res.json({ message: "User metadata updated", user: updatedUser });
      } catch (error) {
        console.error("Error updating user:", error);
        res.status(500).json({ error: "Failed to update user metadata" });
      }
    });

    // ---------- SOCKET.IO with CORS ----------
    // Pass the same allowed origins into Socket.IO
    socketHandler(httpServer, {
      cors: {
        origin: allowed,
        methods: ["GET","POST"],
        credentials: true
      },
      transports: ["websocket", "polling"], // keep both unless you want ws only
      path: "/socket.io" // default; keep explicit
    });

    // ---------- LISTEN ----------
    const PORT = process.env.PORT || 5000;
    httpServer.listen(PORT, "0.0.0.0", () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`Allowed origins: ${allowed.join(", ") || "(none)"}`);
    });
  } catch (error) {
    console.error("Failed to initialize server:", error);
    process.exit(1);
  }
};

initializeServer();
