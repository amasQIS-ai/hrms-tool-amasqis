import { Server as SocketIOServer } from "socket.io";
import dotenv from "dotenv";
import router from "./router.js";
import { clerkClient, verifyToken } from "@clerk/express";
dotenv.config();

// Environment / rate limiting
const isDevelopment =
  process.env.NODE_ENV === "development" ||
  process.env.NODE_ENV !== "production";

const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 100; // Max requests per minute per user

const checkRateLimit = (userId) => {
  if (isDevelopment) return true; // Skip in development

  const now = Date.now();
  const userKey = `user:${userId}`;

  if (!rateLimitMap.has(userKey)) {
    rateLimitMap.set(userKey, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return true;
  }

  const userLimit = rateLimitMap.get(userKey);

  if (now > userLimit.resetTime) {
    rateLimitMap.set(userKey, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return true;
  }

  if (userLimit.count >= RATE_LIMIT_MAX_REQUESTS) return false;

  userLimit.count++;
  return true;
};

// Periodic cleanup (production only)
if (!isDevelopment) {
  setInterval(() => {
    const now = Date.now();
    for (const [key, value] of rateLimitMap.entries()) {
      if (now > value.resetTime) {
        rateLimitMap.delete(key);
      }
    }
  }, RATE_LIMIT_WINDOW);
}

// ---- Socket.IO CORS allowlist (normalized, no "*") ----
const norm = (u) => (u ? u.replace(/\/$/, "") : u);

const envAllowed = (process.env.ALLOWED_ORIGINS || process.env.FRONTEND_URL || "")
  .split(",")
  .map((s) => norm(s.trim()))
  .filter(Boolean);

const allowedOrigins = [
  ...new Set([
    "https://amasqis.ai",
    "https://devhrms-pm.amasqis.ai",
    // Add more static origins here if needed
    ...envAllowed,
    ...(isDevelopment ? ["http://localhost:3000", "http://localhost:5173"] : []),
  ]),
];

// Clerk authorized parties (no trailing slashes) + devmanagertc host
const authorizedParties = [
  "https://devhrms-pm.amasqis.ai",
  "http://localhost:3000",
  "http://185.199.53.177:5000",
  "http://byte.localhost:3000",
  "http://test.localhost:3000",
  "http://dummy.localhost:3000",
  "https://devmanagertc.amasqis.ai",
].map(norm);

// -------------------------------------------------------

export const socketHandler = (httpServer) => {
  const io = new SocketIOServer(httpServer, {
    path: "/socket.io",
    transports: ["websocket", "polling"],
    cors: {
      origin(origin, cb) {
        if (!origin) return cb(null, true); // same-origin / curl
        const o = norm(origin);
        if (allowedOrigins.includes(o)) return cb(null, true);
        return cb(new Error("Socket.IO CORS not allowed: " + origin), false);
      },
      methods: ["GET", "POST"],
      credentials: true,
    },
  });

  io.use(async (socket, next) => {
    console.log("Socket connection attempt...");
    const token = socket.handshake.auth.token;
    console.log("Token received:", token ? "Token present" : "No token");
    if (!token) {
      console.error("No token provided");
      return next(new Error("Authentication error: No token provided"));
    }

    try {
      const verifiedToken = await verifyToken(token, {
        jwtKey: process.env.CLERK_JWT_KEY,
        authorizedParties,
      });

      if (!verifiedToken) {
        console.error("Invalid token");
        return next(new Error("Authentication error: Invalid token"));
      }

      console.log(`Token verified! User ID: ${verifiedToken.sub}`);
      socket.user = verifiedToken;

      let user;
      try {
        user = await clerkClient.users.getUser(verifiedToken.sub);
      } catch (clerkError) {
        console.error(`Failed to fetch user from Clerk:`, clerkError.message);
        console.error(`Clerk error details:`, {
          userId: verifiedToken.sub,
          error: clerkError,
        });
        return next(new Error("Authentication error: Failed to fetch user data"));
      }

      // Store user metadata on socket for security checks
      socket.userMetadata = user.publicMetadata;

      // Role / company handling
      let role = user.publicMetadata?.role;
      let companyId = user.publicMetadata?.companyId || null;

      if (isDevelopment && role === "admin" && !companyId) {
        companyId = "68443081dcdfe43152aebf80";
        console.log(
          `🔧 Development fix: Auto-assigning companyId ${companyId} to admin user`
        );
      }

      console.log(`User ${user.id} metadata:`, {
        role,
        companyId,
        hasVerification: !!user.publicMetadata?.isAdminVerified,
        environment: isDevelopment ? "development" : "production",
        publicMetadata: user.publicMetadata,
      });

      if (!role) {
        if (companyId && user.publicMetadata?.isVerified) {
          role = "employee";
        } else if (isDevelopment && companyId) {
          role = "admin";
          console.log(`[Development] Setting admin role for user ${user.id}`);
        } else {
          role = "public";
        }

        console.warn(`User ${user.id} had no role assigned, defaulting to: ${role}`);

        await clerkClient.users.updateUserMetadata(user.id, {
          publicMetadata: { ...user.publicMetadata, role, companyId },
        });
      } else {
        console.log(`User ${user.id} has existing role: ${role}`);
      }

      // Admin verification rules
      if (role === "admin") {
        console.log(`Checking admin access for user ${user.id}...`);
        if (isDevelopment) {
          if (!companyId) {
            console.error(`Admin user ${user.id} missing companyId in development`);
            return next(new Error("Admin users must have a companyId"));
          }
          console.log(
            `✅ Development: Allowing admin access for user ${user.id} with companyId: ${companyId}`
          );
        } else {
          if (!companyId || !user.publicMetadata?.isAdminVerified) {
            console.error(
              `Unauthorized admin access attempt by user ${user.id} in production`
            );
            return next(new Error("Unauthorized: Admin access requires verification"));
          }
          console.log(`✅ Production: Verified admin access for user ${user.id}`);
        }
      }

      // Mark socket as authenticated
      socket.userId = verifiedToken.sub;
      socket.role = role;
      socket.companyId = companyId;
      socket.authenticated = true;

      // Rate limit helper
      socket.checkRateLimit = () => checkRateLimit(socket.userId);

      console.log(
        `Socket authentication complete for user: ${verifiedToken.sub}, role: ${role}, company: ${companyId}`
      );

      // Join role-based rooms
      switch (role) {
        case "superadmin":
          socket.join("superadmin_room");
          console.log(`User joined superadmin_room`);
          break;
        case "admin":
          if (companyId) {
            socket.join(`admin_room_${companyId}`);
            socket.join(`company_${companyId}`);
            socket.join(`user_${user.id}`);
            console.log(`User joined admin_room_${companyId}`);
          } else {
            console.warn(`Admin user ${user.id} has no companyId`);
            return next(new Error("Admin user must have a companyId"));
          }
          break;
        case "hr":
          if (companyId) {
            socket.join(`hr_room_${companyId}`);
            socket.join(`company_${companyId}`);
            socket.join(`user_${user.id}`);
            console.log(`User joined hr_room_${companyId}`);
          }
          break;
        case "employee":
          if (companyId) {
            socket.join(`employee_room_${companyId}`);
            socket.join(`company_${companyId}`);
            socket.join(`user_${user.id}`);
            console.log(`User joined employee_room_${companyId}`);
          }
          break;
        default:
          console.log(`User with role '${role}' connected`);
          break;
      }

      return next();
    } catch (err) {
      console.error("Token verification failed:", err.message);
      return next(new Error("Authentication error: Token verification failed"));
    }
  });

  io.on("connection", (socket) => {
    console.log(
      `Client connected: ${socket.id}, Role: ${socket.role}, Company: ${
        socket.companyId || "None"
      }, UserId: ${socket.userId || "None"}`
    );
    console.log(`Socket user metadata:`, socket.userMetadata);
    console.log(`Socket user object:`, socket.user);

    const role = socket.role || "guest";
    router(socket, io, role);

    socket.on("disconnect", () => {
      console.log(`Client disconnected: ${socket.id}`);
    });
  });
};
