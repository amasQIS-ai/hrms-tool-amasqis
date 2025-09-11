// socket/index.js  (ESM)

import { Server as SocketIOServer } from "socket.io";
import dotenv from "dotenv";
import router from "./router.js";
import { clerkClient, verifyToken } from "@clerk/express";

dotenv.config();

/* ------------------------- helpers / config ------------------------- */

const isDevelopment =
  process.env.NODE_ENV === "development" || process.env.NODE_ENV !== "production";

const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 100; // per user per minute
const rateLimitMap = new Map();

const norm = (u) => (u ? u.replace(/\/$/, "") : u); // strip trailing slash

// Build allowed origins from env + known hosts
const envAllowed = (process.env.ALLOWED_ORIGINS || process.env.FRONTEND_URL || "")
  .split(",")
  .map((s) => norm(s.trim()))
  .filter(Boolean);

const devAllowed = [
  "http://localhost:3000",
  "http://localhost:5173",
  "http://byte.localhost:3000",
  "http://test.localhost:3000",
  "http://dummy.localhost:3000",
];

const baseAllowed = [
  "https://amasqis.ai",
  "https://devhrms-pm.amasqis.ai",
  // add more static prod origins here if needed
];

const allowedOrigins = Array.from(
  new Set([
    ...baseAllowed.map(norm),
    ...envAllowed,
    ...(isDevelopment ? devAllowed.map(norm) : []),
  ])
).filter(Boolean);

// Authorized parties for Clerk (must be exact origins, NO trailing slash)
const authorizedParties = Array.from(
  new Set(
    [
      "https://devmanagertc.amasqis.ai",
      "https://devhrms-pm.amasqis.ai",
      "http://localhost:3000",
      "http://byte.localhost:3000",
      "http://test.localhost:3000",
      "http://dummy.localhost:3000",
      "http://185.199.53.177:5000",
    ].map(norm)
  )
);

/* ---------------------------- rate limiting ---------------------------- */

const checkRateLimit = (userId) => {
  if (isDevelopment) return true; // disabled in dev
  const now = Date.now();
  const key = `user:${userId}`;
  const info = rateLimitMap.get(key);

  if (!info) {
    rateLimitMap.set(key, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return true;
  }
  if (now > info.resetTime) {
    rateLimitMap.set(key, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return true;
  }
  if (info.count >= RATE_LIMIT_MAX_REQUESTS) return false;
  info.count++;
  return true;
};

// periodic cleanup in prod
if (!isDevelopment) {
  setInterval(() => {
    const now = Date.now();
    for (const [key, value] of rateLimitMap.entries()) {
      if (now > value.resetTime) rateLimitMap.delete(key);
    }
  }, RATE_LIMIT_WINDOW);
}

/* ----------------------------- socket.io ------------------------------ */
/**
 * @param {import('http').Server} httpServer
 * @param {import('socket.io').ServerOptions} ioOptions (optional)
 */
export const socketHandler = (httpServer, ioOptions = {}) => {
  const io = new SocketIOServer(httpServer, {
    path: "/socket.io",
    transports: ["websocket", "polling"],
    cors: {
      // IMPORTANT: no "*" since credentials:true
      origin: (origin, cb) => {
        if (!origin) return cb(null, true); // same-origin or server-side
        const o = norm(origin);
        if (allowedOrigins.includes(o)) return cb(null, true);
        return cb(new Error("Socket.IO CORS not allowed: " + origin), false);
      },
      methods: ["GET", "POST"],
      credentials: true,
    },
    ...ioOptions,
  });

  // auth middleware (Clerk JWT)
  io.use(async (socket, next) => {
    try {
      console.log("Socket connection attempt...");
      const token = socket.handshake?.auth?.token;
      if (!token) return next(new Error("Authentication error: No token provided"));

      const verified = await verifyToken(token, {
        jwtKey: process.env.CLERK_JWT_KEY,
        authorizedParties,
      });
      if (!verified) return next(new Error("Authentication error: Invalid token"));

      socket.user = verified; // raw claims

      // fetch user for metadata/role enforcement
      let user;
      try {
        user = await clerkClient.users.getUser(verified.sub);
      } catch (e) {
        console.error("Failed to fetch user from Clerk:", e?.message || e);
        return next(new Error("Authentication error: Failed to fetch user data"));
      }

      // role & company from publicMetadata
      let role = user.publicMetadata?.role;
      let companyId = user.publicMetadata?.companyId || null;

      if (!role) {
        if (companyId && user.publicMetadata?.isVerified) {
          role = "employee";
        } else if (isDevelopment && companyId) {
          role = "admin"; // dev convenience
          console.log(`[Dev] Assigning admin role for ${user.id} (company ${companyId})`);
        } else {
          role = "public";
        }
        await clerkClient.users.updateUserMetadata(user.id, {
          publicMetadata: { ...user.publicMetadata, role, companyId },
        });
      }

      if (role === "admin") {
        if (isDevelopment) {
          if (!companyId) return next(new Error("Admin user must have a companyId (dev)"));
        } else {
          if (!companyId || !user.publicMetadata?.isAdminVerified) {
            return next(new Error("Unauthorized: Admin access requires verification"));
          }
        }
      }

      // attach useful props
      socket.userId = verified.sub;
      socket.role = role;
      socket.companyId = companyId;
      socket.userMetadata = user.publicMetadata;
      socket.authenticated = true;

      // per-socket rate limit helper
      socket.checkRateLimit = () => checkRateLimit(socket.userId);

      return next();
    } catch (err) {
      return next(new Error("Authentication error: " + (err?.message || "failed")));
    }
  });

  io.on("connection", (socket) => {
    console.log(
      `Socket connected: ${socket.id} | user=${socket.userId || "n/a"} | role=${socket.role || "guest"} | company=${socket.companyId || "n/a"}`
    );

    // role-scoped rooms
    switch (socket.role) {
      case "superadmin":
        socket.join("superadmin_room");
        break;
      case "admin":
        if (socket.companyId) {
          socket.join(`admin_room_${socket.companyId}`);
          socket.join(`company_${socket.companyId}`);
          socket.join(`user_${socket.userId}`);
        }
        break;
      case "hr":
        if (socket.companyId) {
          socket.join(`hr_room_${socket.companyId}`);
          socket.join(`company_${socket.companyId}`);
          socket.join(`user_${socket.userId}`);
        }
        break;
      case "employee":
        if (socket.companyId) {
          socket.join(`employee_room_${socket.companyId}`);
          socket.join(`company_${socket.companyId}`);
          socket.join(`user_${socket.userId}`);
        }
        break;
      default:
        break;
    }

    // attach your feature routes
    const role = socket.role || "guest";
    router(socket, io, role);

    socket.on("disconnect", () => {
      console.log(`Socket disconnected: ${socket.id}`);
    });
  });

  console.log(
    "[socket.io] allowed origins:",
    allowedOrigins.length ? allowedOrigins.join(", ") : "(none)"
  );

  return io;
};
