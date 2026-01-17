#!/usr/bin/env bash
set -euo pipefail

OUTDIR="KOVERIST-package"
ZIPNAME="KOVERIST-package.zip"

if [ -d "$OUTDIR" ]; then
  echo "Removing existing $OUTDIR"
  rm -rf "$OUTDIR"
fi
mkdir -p "$OUTDIR"

echo "Creating project files under $OUTDIR ..."

# Backend package.json
mkdir -p "$OUTDIR/backend"
cat > "$OUTDIR/backend/package.json" <<'EOF'
{
  "name": "koverist-backend",
  "version": "0.1.0",
  "private": true,
  "scripts": {
    "dev": "ts-node-dev --respawn --transpile-only src/server.ts",
    "build": "tsc",
    "start": "node dist/server.js",
    "prisma:generate": "prisma generate",
    "prisma:migrate": "prisma migrate dev",
    "test": "jest --runInBand"
  },
  "dependencies": {
    "@prisma/client": "^4.10.1",
    "bcrypt": "^5.1.0",
    "cors": "^2.8.5",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.0",
    "morgan": "^1.10.0"
  },
  "devDependencies": {
    "prisma": "^4.10.1",
    "ts-node-dev": "^2.0.0",
    "typescript": "^4.9.5",
    "@types/express": "^4.17.17",
    "@types/jsonwebtoken": "^9.0.1",
    "@types/bcrypt": "^5.0.0",
    "@types/node": "^18.11.18",
    "jest": "^29.0.0",
    "ts-jest": "^29.0.0",
    "@types/jest": "^29.0.0"
  }
}
EOF

# Prisma schema
mkdir -p "$OUTDIR/backend/prisma"
cat > "$OUTDIR/backend/prisma/schema.prisma" <<'EOF'
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

enum Role {
  STANDARD
  MANAGEMENT
}

enum Status {
  ACTIVE
  FROZEN
  QUIT
  REMOVED
}

enum Category {
  ENTERTAINMENT
  KOVERIST
  SVS
  IDG
  OTHER
}

enum CardType {
  PNG_UPLOAD
  ONSITE_EDITOR
}

enum AnnouncementType {
  OPEN_AUDITION
  CLOSED_AUDITION
  PROJECT
  COLLABORATION
  BRIEF
  COMEBACK
  QUESTION
  OTHER
}

enum TargetType {
  USER
  CARD
  ANNOUNCEMENT
}

enum ReportStatus {
  PENDING
  REVIEWED
  ACTIONED
}

enum ReportOutcome {
  NONE
  FREEZE
  REMOVE
}

enum ActionType {
  FREEZE
  REMOVE
  ROLE_ASSIGN
  SUBLABEL_APPROVE
}

model User {
  id            Int       @id @default(autoincrement())
  username      String    @unique
  email         String    @unique
  passwordHash  String
  role          Role      @default(STANDARD)
  status        Status    @default(ACTIVE)
  category      Category
  joinDate      DateTime  @default(now())
  profileImage  String?
  bio           String?
  createdAt     DateTime  @default(now())
  updatedAt     DateTime  @updatedAt

  card          Card?
  announcements Announcement[]
  sentMessages  Message[] @relation("sent")
  receivedMessages Message[] @relation("received")
  mainSublabels SubLabel[] @relation("main")
  subOf         SubLabel[] @relation("sub")
  reportsMade   Report[]   @relation("reporter")
  reportsReviewed Report[] @relation("reviewer")
  actionLogs    ActionLog[]
}

model Card {
  id          Int       @id @default(autoincrement())
  user        User      @relation(fields: [userId], references: [id])
  userId      Int       @unique
  type        CardType
  elements    Json?
  statusLabel Status
  createdAt   DateTime  @default(now())
  updatedAt   DateTime  @updatedAt
}

model Announcement {
  id           Int              @id @default(autoincrement())
  user         User             @relation(fields: [userId], references: [id])
  userId       Int
  type         AnnouncementType
  content      String
  externalLink String?
  deadline     DateTime?
  createdAt    DateTime         @default(now())
  updatedAt    DateTime         @updatedAt
  likesCount   Int              @default(0)
  comments     Json?
}

model Message {
  id          Int      @id @default(autoincrement())
  sender      User     @relation("sent", fields: [senderId], references: [id])
  senderId    Int
  recipient   User     @relation("received", fields: [recipientId], references: [id])
  recipientId Int
  content     String
  readStatus  Boolean  @default(false)
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
}

model SubLabel {
  id           Int      @id @default(autoincrement())
  mainLabel    User     @relation("main", fields: [mainLabelId], references: [id])
  mainLabelId  Int
  subLabel     User     @relation("sub", fields: [subLabelId], references: [id])
  subLabelId   Int
  approved     Boolean  @default(false)
  createdAt    DateTime @default(now())
  updatedAt    DateTime @updatedAt
}

model Report {
  id          Int         @id @default(autoincrement())
  reporter    User        @relation("reporter", fields: [reporterId], references: [id])
  reporterId  Int
  targetType  TargetType
  targetId    Int
  reason      String
  evidence    Json
  status      ReportStatus @default(PENDING)
  outcome     ReportOutcome @default(NONE)
  reviewedBy  User?       @relation("reviewer", fields: [reviewedById], references: [id])
  reviewedById Int?
  createdAt   DateTime    @default(now())
  updatedAt   DateTime    @updatedAt
}

model ActionLog {
  id         Int       @id @default(autoincrement())
  actor      User      @relation(fields: [actorId], references: [id])
  actorId    Int
  actionType ActionType
  targetId   Int
  timestamp  DateTime  @default(now())
  notes      String?
}

/*
BootstrapState: singleton table to track bootstrap enablement (id = 1)
BootstrapAudit: immutable audit records (sealed marks permanent completion)
*/
model BootstrapState {
  id         Int      @id @default(1)
  enabled    Boolean  @default(true)
  limit      Int      @default(2)
  createdAt  DateTime @default(now())
  updatedAt  DateTime @updatedAt
  completedAt DateTime?
}

model BootstrapAudit {
  id         Int      @id @default(autoincrement())
  createdBy  Int?
  note       String?
  sealed     Boolean  @default(false)
  createdAt  DateTime @default(now())

  @@index([sealed])
}
EOF

# Backend source tree
mkdir -p "$OUTDIR/backend/src/utils" "$OUTDIR/backend/src/middleware" "$OUTDIR/backend/src/routes" "$OUTDIR/backend/src/tests"

# src/server.ts
cat > "$OUTDIR/backend/src/server.ts" <<'EOF'
import express from "express";
import morgan from "morgan";
import cors from "cors";
import { PrismaClient } from "@prisma/client";
import authRoutes from "./routes/auth";
import userRoutes from "./routes/users";
import cardRoutes from "./routes/cards";
import announcementRoutes from "./routes/announcements";
import reportRoutes from "./routes/reports";
import managementRoutes from "./routes/management";
import publicRoutes from "./routes/public";
import { ensureBootstrapStateExists } from "./utils/bootstrap";

const prisma = new PrismaClient();

const app = express();
app.use(cors());
app.use(express.json({ limit: "5mb" }));
app.use(morgan("dev"));

// attach prisma to req for simple access
declare global {
  namespace Express {
    interface Request {
      prisma?: PrismaClient;
      user?: any;
    }
  }
}
app.use((req, _res, next) => {
  req.prisma = prisma;
  next();
});

/*
  Ensure bootstrap state exists on startup (singleton row).
*/
(async () => {
  try {
    const limit = Number(process.env.BOOTSTRAP_MANAGEMENT_LIMIT ?? 2);
    await ensureBootstrapStateExists(limit);
    console.log("Bootstrap state ensured");
  } catch (err) {
    console.error("Error ensuring bootstrap state:", err);
  }
})();

app.use("/", publicRoutes);
app.use("/auth", authRoutes);
app.use("/users", userRoutes);
app.use("/cards", cardRoutes);
app.use("/announcements", announcementRoutes);
app.use("/reports", reportRoutes);
app.use("/management", managementRoutes);

const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`KOVERIST backend listening on ${port}`);
});
EOF

# src/utils/jwt.ts
cat > "$OUTDIR/backend/src/utils/jwt.ts" <<'EOF'
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET || "replace-me";

export function signToken(payload: object, expiresIn = "7d") {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

export function verifyToken(token: string) {
  return jwt.verify(token, JWT_SECRET);
}
EOF

# src/middleware/auth.ts (latest management-aware)
cat > "$OUTDIR/backend/src/middleware/auth.ts" <<'EOF'
import { Request, Response, NextFunction } from "express";
import { verifyToken } from "../utils/jwt";

/**
 * Authentication & authorization middleware.
 *
 * - authenticate: require a valid Bearer JWT and attach minimal payload to req.user
 * - optionalAuthenticate: attach req.user when a valid token present, otherwise continue
 * - requireManagement: checks current DB state to confirm the requesting user still has MANAGEMENT role
 */

declare global {
  namespace Express {
    interface Request {
      user?: { userId: number; role?: string; status?: string };
      prisma?: any;
    }
  }
}

export async function authenticate(req: Request, res: Response, next: NextFunction) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "Missing token" });
  const token = auth.slice(7);
  try {
    const payload = verifyToken(token) as any;
    req.user = { userId: payload.userId, role: payload.role, status: payload.status };
    return next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

export async function optionalAuthenticate(req: Request, _res: Response, next: NextFunction) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) {
    return next();
  }
  const token = auth.slice(7);
  try {
    const payload = verifyToken(token) as any;
    req.user = { userId: payload.userId, role: payload.role, status: payload.status };
  } catch (err) {
    // ignore invalid token for optional auth
  }
  return next();
}

export async function requireManagement(req: Request, res: Response, next: NextFunction) {
  if (!req.user) return res.status(401).json({ error: "Not authenticated" });
  if (!req.prisma) return res.status(500).json({ error: "Prisma not available on request" });

  try {
    const user = await req.prisma.user.findUnique({ where: { id: req.user.userId }, select: { role: true, status: true } });
    if (!user) return res.status(401).json({ error: "User not found" });
    if (user.role !== "MANAGEMENT") return res.status(403).json({ error: "Management only" });
    if (user.status === "REMOVED") return res.status(403).json({ error: "Account removed" });
    req.user.role = user.role;
    req.user.status = user.status;
    return next();
  } catch (err) {
    return res.status(500).json({ error: "Error checking management role" });
  }
}
EOF

# src/utils/bootstrap.ts
cat > "$OUTDIR/backend/src/utils/bootstrap.ts" <<'EOF'
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

/**
 * Bootstrap helper for management assignment.
 * - Uses BootstrapAudit.sealed to make bootstrap irreversible via app logic.
 * - Requires BOOTSTRAP_SETUP_SECRET at initial creation to permit enabling bootstrap.
 */

export async function ensureBootstrapStateExists(limitFromEnv?: number) {
  const sealedAudit = await prisma.bootstrapAudit.findFirst({ where: { sealed: true } });
  if (sealedAudit) {
    const existing = await prisma.bootstrapState.findUnique({ where: { id: 1 } });
    if (existing) {
      if (existing.enabled) {
        return await prisma.bootstrapState.update({
          where: { id: 1 },
          data: { enabled: false, completedAt: new Date() },
        });
      }
      return existing;
    } else {
      const limit = limitFromEnv ?? Number(process.env.BOOTSTRAP_MANAGEMENT_LIMIT ?? 2);
      return await prisma.bootstrapState.create({
        data: {
          id: 1,
          enabled: false,
          limit,
          completedAt: new Date(),
        },
      });
    }
  }

  const existing = await prisma.bootstrapState.findUnique({ where: { id: 1 } });
  if (existing) return existing;

  const limit = limitFromEnv ?? Number(process.env.BOOTSTRAP_MANAGEMENT_LIMIT ?? 2);
  const allowBootstrap = !!process.env.BOOTSTRAP_SETUP_SECRET;

  return await prisma.bootstrapState.create({
    data: {
      id: 1,
      enabled: allowBootstrap,
      limit,
      completedAt: allowBootstrap ? null : undefined,
    },
  });
}

export async function getBootstrapState() {
  return await prisma.bootstrapState.findUnique({ where: { id: 1 } });
}

export async function sealBootstrapAudit(note?: string, actorUserId?: number) {
  const audit = await prisma.bootstrapAudit.create({
    data: {
      createdBy: actorUserId ?? null,
      note: note ?? "Bootstrap completed and sealed.",
      sealed: true,
    },
  });

  const state = await prisma.bootstrapState.upsert({
    where: { id: 1 },
    update: { enabled: false, completedAt: new Date() },
    create: { id: 1, enabled: false, limit: Number(process.env.BOOTSTRAP_MANAGEMENT_LIMIT ?? 2), completedAt: new Date() },
  });

  return { audit, state };
}
EOF

# src/utils/management.ts
cat > "$OUTDIR/backend/src/utils/management.ts" <<'EOF'
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export async function canDemoteManagement(targetUserId: number) {
  const target = await prisma.user.findUnique({ where: { id: targetUserId } });
  if (!target) throw new Error("Target user not found");
  if (target.role !== "MANAGEMENT") return true;
  const managementCount = await prisma.user.count({ where: { role: "MANAGEMENT" } });
  return managementCount > 1;
}
EOF

# src/routes/auth.ts
cat > "$OUTDIR/backend/src/routes/auth.ts" <<'EOF'
import express from "express";
import bcrypt from "bcrypt";
import { signToken } from "../utils/jwt";
import { PrismaClient } from "@prisma/client";
import { ensureBootstrapStateExists } from "../utils/bootstrap";

const router = express.Router();
const prisma = new PrismaClient();

router.post("/signup", async (req, res) => {
  const { username, email, password, category } = req.body;
  if (!username || !email || !password || !category) {
    return res.status(400).json({ error: "username, email, password, category required" });
  }
  const hashed = await bcrypt.hash(password, 10);

  const bootstrap = await ensureBootstrapStateExists();

  try {
    const result = await prisma.$transaction(async (tx) => {
      const user = await tx.user.create({
        data: {
          username,
          email,
          passwordHash: hashed,
          category,
        },
      });

      if (bootstrap.enabled) {
        const managementCount = await tx.user.count({ where: { role: "MANAGEMENT" } });
        const limit = bootstrap.limit ?? Number(process.env.BOOTSTRAP_MANAGEMENT_LIMIT ?? 2);
        if (managementCount < limit) {
          await tx.user.update({ where: { id: user.id }, data: { role: "MANAGEMENT" } });
          await tx.actionLog.create({
            data: {
              actorId: user.id,
              actionType: "ROLE_ASSIGN",
              targetId: user.id,
              notes: `Bootstrap assignment (management)`,
            },
          });

          if (managementCount + 1 >= limit) {
            await tx.bootstrapState.update({
              where: { id: 1 },
              data: { enabled: false, completedAt: new Date() },
            });
            await tx.bootstrapAudit.create({
              data: {
                createdBy: user.id,
                note: `Bootstrap completed: ${managementCount + 1} management accounts created`,
                sealed: true,
              },
            });
          }

          const updated = await tx.user.findUnique({ where: { id: user.id } });
          return updated!;
        }
      }

      return user;
    });

    const token = signToken({ userId: result.id, role: result.role, status: result.status });
    return res.json({ token, user: { id: result.id, username: result.username, role: result.role, status: result.status } });
  } catch (err: any) {
    const message = err?.meta?.target ? `Duplicate field: ${err.meta.target}` : err.message || "Could not create user";
    return res.status(400).json({ error: message });
  }
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(401).json({ error: "Invalid credentials" });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });
  if (user.status === "REMOVED") return res.status(403).json({ error: "Account removed" });
  const token = signToken({ userId: user.id, role: user.role, status: user.status });
  return res.json({ token, user: { id: user.id, username: user.username, role: user.role, status: user.status } });
});

export default router;
EOF

# src/routes/users.ts
cat > "$OUTDIR/backend/src/routes/users.ts" <<'EOF'
import express from "express";
import { authenticate, requireActive, requireManagement } from "../middleware/auth";
import { canDemoteManagement } from "../utils/management";
const router = express.Router();

router.get("/:id", async (req, res) => {
  const prisma = req.prisma!;
  const id = Number(req.params.id);
  const user = await prisma.user.findUnique({
    where: { id },
    include: { card: true },
  });
  if (!user) return res.status(404).json({ error: "Not found" });
  if (user.status === "REMOVED") {
    return res.status(403).json({ error: "Profile unavailable" });
  }
  return res.json({
    id: user.id,
    username: user.username,
    category: user.category,
    status: user.status,
    joinDate: user.joinDate,
    bio: user.bio,
    profileImage: user.profileImage,
    card: user.card,
  });
});

router.patch("/:id", authenticate, requireActive, async (req, res) => {
  const prisma = req.prisma!;
  const id = Number(req.params.id);
  if (req.user.userId !== id) return res.status(403).json({ error: "Can only update your profile" });
  const { username, bio, profileImage, category } = req.body;
  const data: any = {};
  if (username) data.username = username;
  if (bio) data.bio = bio;
  if (profileImage) data.profileImage = profileImage;
  if (category) data.category = category;
  const user = await prisma.user.update({ where: { id }, data });
  return res.json({ user });
});

router.patch("/:id/status", authenticate, requireManagement, async (req, res) => {
  const prisma = req.prisma!;
  const id = Number(req.params.id);
  const { status } = req.body;
  if (!["ACTIVE", "FROZEN", "QUIT", "REMOVED"].includes(status)) return res.status(400).json({ error: "Invalid status" });
  const user = await prisma.user.update({ where: { id }, data: { status } });
  await prisma.card.updateMany({ where: { userId: id }, data: { statusLabel: status } });
  await prisma.actionLog.create({
    data: {
      actorId: req.user.userId,
      actionType: status === "REMOVED" ? "REMOVE" : "FREEZE",
      targetId: id,
      notes: `Status set to ${status}`,
    },
  });
  return res.json({ user });
});

router.patch("/:id/role", authenticate, requireManagement, async (req, res) => {
  const prisma = req.prisma!;
  const id = Number(req.params.id);
  const { role } = req.body;
  if (!["STANDARD", "MANAGEMENT"].includes(role)) return res.status(400).json({ error: "Invalid role" });

  const target = await prisma.user.findUnique({ where: { id } });
  if (!target) return res.status(404).json({ error: "Target user not found" });

  if (target.role === "MANAGEMENT" && role === "STANDARD") {
    const safe = await canDemoteManagement(id);
    if (!safe) return res.status(403).json({ error: "Cannot remove the last remaining management account" });
  }

  const updated = await prisma.user.update({ where: { id }, data: { role } });

  await prisma.actionLog.create({
    data: {
      actorId: req.user.userId,
      actionType: "ROLE_ASSIGN",
      targetId: id,
      notes: `Role set to ${role} by management (actor ${req.user.userId})`,
    },
  });

  return res.json({ user: updated });
});

router.patch("/:id/quit", authenticate, async (req, res) => {
  const prisma = req.prisma!;
  const id = Number(req.params.id);
  if (req.user.userId !== id) return res.status(403).json({ error: "Can only quit your own account" });
  const user = await prisma.user.update({ where: { id }, data: { status: "QUIT" } });
  await prisma.card.updateMany({ where: { userId: id }, data: { statusLabel: "QUIT" } });
  return res.json({ message: "Account set to QUIT" });
});

export default router;
EOF

# src/routes/cards.ts
cat > "$OUTDIR/backend/src/routes/cards.ts" <<'EOF'
import express from "express";
import { authenticate, requireActive } from "../middleware/auth";
const router = express.Router();

router.get("/:id", async (req, res) => {
  const prisma = req.prisma!;
  const id = Number(req.params.id);
  const card = await prisma.card.findUnique({ where: { id } });
  if (!card) return res.status(404).json({ error: "Card not found" });
  return res.json(card);
});

router.post("/", authenticate, requireActive, async (req, res) => {
  const prisma = req.prisma!;
  const userId = req.user.userId;
  const { type, elements } = req.body;
  try {
    const card = await prisma.card.create({
      data: {
        userId,
        type,
        elements,
        statusLabel: "ACTIVE",
      },
    });
    return res.json(card);
  } catch (err: any) {
    return res.status(400).json({ error: "Could not create card", details: err.message });
  }
});

router.patch("/:id", authenticate, requireActive, async (req, res) => {
  const prisma = req.prisma!;
  const id = Number(req.params.id);
  const card = await prisma.card.findUnique({ where: { id } });
  if (!card) return res.status(404).json({ error: "Card not found" });
  if (card.userId !== req.user.userId) return res.status(403).json({ error: "Not allowed" });
  const { elements, type } = req.body;
  const updated = await prisma.card.update({ where: { id }, data: { elements, type } });
  return res.json(updated);
});

router.delete("/:id", authenticate, requireActive, async (req, res) => {
  const prisma = req.prisma!;
  const id = Number(req.params.id);
  const card = await prisma.card.findUnique({ where: { id } });
  if (!card) return res.status(404).json({ error: "Card not found" });
  if (card.userId !== req.user.userId) return res.status(403).json({ error: "Not allowed" });
  if (card.type !== "PNG_UPLOAD") return res.status(400).json({ error: "Only PNG upload type can be deleted to switch" });
  await prisma.card.delete({ where: { id } });
  return res.json({ message: "PNG card deleted; you can now create an on-site card." });
});

export default router;
EOF

# src/routes/announcements.ts
cat > "$OUTDIR/backend/src/routes/announcements.ts" <<'EOF'
import express from "express";
import { authenticate, requireActive } from "../middleware/auth";
const router = express.Router();

router.get("/", async (req, res) => {
  const prisma = req.prisma!;
  const anns = await prisma.announcement.findMany({
    where: {
      user: { status: "ACTIVE" },
    },
    orderBy: { createdAt: "desc" },
  });
  return res.json(anns);
});

router.get("/type/:type", async (req, res) => {
  const prisma = req.prisma!;
  const type = req.params.type.toUpperCase();
  const anns = await prisma.announcement.findMany({
    where: { type: type as any, user: { status: "ACTIVE" } },
    orderBy: { createdAt: "desc" },
  });
  return res.json(anns);
});

router.post("/", authenticate, requireActive, async (req, res) => {
  const prisma = req.prisma!;
  const userId = req.user.userId;
  const { type, content, externalLink, deadline } = req.body;
  const data: any = { userId, type, content, externalLink };
  if (deadline) data.deadline = new Date(deadline);
  if (type === "QUESTION") data.comments = [];
  const ann = await prisma.announcement.create({ data });
  return res.json(ann);
});

router.patch("/:id", authenticate, requireActive, async (req, res) => {
  const prisma = req.prisma!;
  const id = Number(req.params.id);
  const ann = await prisma.announcement.findUnique({ where: { id } });
  if (!ann) return res.status(404).json({ error: "Not found" });
  if (ann.userId !== req.user.userId) return res.status(403).json({ error: "Not allowed" });
  const { content, externalLink, deadline } = req.body;
  const updated = await prisma.announcement.update({ where: { id }, data: { content, externalLink, deadline } });
  return res.json(updated);
});

router.post("/:id/like", authenticate, requireActive, async (req, res) => {
  const prisma = req.prisma!;
  const id = Number(req.params.id);
  const ann = await prisma.announcement.update({ where: { id }, data: { likesCount: { increment: 1 } } });
  return res.json({ likesCount: ann.likesCount });
});

router.get("/:id/comments", async (req, res) => {
  const prisma = req.prisma!;
  const id = Number(req.params.id);
  const ann = await prisma.announcement.findUnique({ where: { id } });
  if (!ann) return res.status(404).json({ error: "Not found" });
  if (ann.type !== "QUESTION") return res.status(400).json({ error: "Comments only for Question type" });
  return res.json(ann.comments || []);
});

router.post("/:id/comments", authenticate, requireActive, async (req, res) => {
  const prisma = req.prisma!;
  const id = Number(req.params.id);
  const { comment } = req.body;
  const ann = await prisma.announcement.findUnique({ where: { id } });
  if (!ann) return res.status(404).json({ error: "Not found" });
  if (ann.type !== "QUESTION") return res.status(400).json({ error: "Comments only for Question type" });
  const comments = ann.comments || [];
  const newComments = [...comments, { authorId: req.user.userId, text: comment, createdAt: new Date() }];
  const updated = await prisma.announcement.update({ where: { id }, data: { comments: newComments } });
  return res.json(updated.comments);
});

export default router;
EOF

# src/routes/reports.ts
cat > "$OUTDIR/backend/src/routes/reports.ts" <<'EOF'
import express from "express";
import { authenticate } from "../middleware/auth";
const router = express.Router();

router.post("/", authenticate, async (req, res) => {
  const prisma = req.prisma!;
  const reporterId = req.user.userId;
  const { targetType, targetId, reason, evidence } = req.body;
  if (!targetType || !targetId || !reason || !evidence) return res.status(400).json({ error: "Missing fields" });
  const report = await prisma.report.create({
    data: {
      reporterId,
      targetType,
      targetId: Number(targetId),
      reason,
      evidence,
      status: "PENDING",
      outcome: "NONE",
    },
  });
  return res.json({ message: "Report received. No further action needed.", reportId: report.id });
});

router.get("/", authenticate, async (req, res) => {
  const prisma = req.prisma!;
  if (req.user.role !== "MANAGEMENT") return res.status(403).json({ error: "Management only" });
  const reports = await prisma.report.findMany({ orderBy: { createdAt: "desc" } });
  return res.json(reports);
});

export default router;
EOF

# src/routes/management.ts
cat > "$OUTDIR/backend/src/routes/management.ts" <<'EOF'
import express from "express";
import { authenticate, requireManagement } from "../middleware/auth";

const router = express.Router();

router.use(authenticate, requireManagement);

router.patch("/users/:id/status", async (req, res) => {
  const prisma = req.prisma!;
  const actorId = req.user!.userId;
  const targetId = Number(req.params.id);
  const { status } = req.body;

  if (!["ACTIVE", "FROZEN", "QUIT", "REMOVED"].includes(status)) {
    return res.status(400).json({ error: "Invalid status" });
  }

  try {
    const user = await prisma.user.update({
      where: { id: targetId },
      data: { status },
    });

    await prisma.card.updateMany({
      where: { userId: targetId },
      data: { statusLabel: status },
    });

    const actionType = status === "REMOVED" ? "REMOVE" : status === "FROZEN" ? "FREEZE" : "ROLE_ASSIGN";
    await prisma.actionLog.create({
      data: {
        actorId,
        actionType: actionType as any,
        targetId,
        notes: `Status changed to ${status} by management ${actorId}`,
      },
    });

    return res.json({ user });
  } catch (err: any) {
    return res.status(500).json({ error: "Could not change status", details: err.message });
  }
});

router.get("/reports", async (_req, res) => {
  const prisma = req.prisma!;
  try {
    const reports = await prisma.report.findMany({
      where: { status: "PENDING" },
      orderBy: { createdAt: "asc" },
    });
    return res.json(reports);
  } catch (err: any) {
    return res.status(500).json({ error: "Could not fetch reports", details: err.message });
  }
});

router.patch("/reports/:id", async (req, res) => {
  const prisma = req.prisma!;
  const actorId = req.user!.userId;
  const reportId = Number(req.params.id);
  const { outcome, notes } = req.body;

  if (!["NONE", "FREEZE", "REMOVE"].includes(outcome)) {
    return res.status(400).json({ error: "Invalid outcome" });
  }

  try {
    const report = await prisma.report.update({
      where: { id: reportId },
      data: {
        status: "REVIEWED",
        outcome: outcome === "NONE" ? "NONE" : outcome === "FREEZE" ? "FREEZE" : "REMOVE",
        reviewedById: actorId,
      },
    });

    if ((outcome === "FREEZE" || outcome === "REMOVE") && report.targetType === "USER") {
      const targetUserId = report.targetId;
      const newStatus = outcome === "FREEZE" ? "FROZEN" : "REMOVED";

      await prisma.user.update({ where: { id: targetUserId }, data: { status: newStatus } });
      await prisma.card.updateMany({ where: { userId: targetUserId }, data: { statusLabel: newStatus } });

      const actionType = outcome === "FREEZE" ? "FREEZE" : "REMOVE";
      await prisma.actionLog.create({
        data: {
          actorId,
          actionType: actionType as any,
          targetId: targetUserId,
          notes: notes ?? `Report ${reportId} resulted in ${newStatus}`,
        },
      });
    } else {
      await prisma.actionLog.create({
        data: {
          actorId,
          actionType: "ROLE_ASSIGN",
          targetId: report.targetId,
          notes: notes ?? `Report ${reportId} reviewed with outcome ${outcome}`,
        },
      });
    }

    return res.json({ report });
  } catch (err: any) {
    return res.status(500).json({ error: "Could not apply report outcome", details: err.message });
  }
});

router.patch("/sub-labels/:id/approve", async (req, res) => {
  const prisma = req.prisma!;
  const actorId = req.user!.userId;
  const id = Number(req.params.id);
  const { approve } = req.body;

  try {
    const sub = await prisma.subLabel.findUnique({ where: { id } });
    if (!sub) return res.status(404).json({ error: "Sub-label request not found" });

    const updated = await prisma.subLabel.update({ where: { id }, data: { approved: !!approve } });

    await prisma.actionLog.create({
      data: {
        actorId,
        actionType: "SUBLABEL_APPROVE" as any,
        targetId: id,
        notes: approve ? `Sub-label ${id} approved` : `Sub-label ${id} set to unapproved`,
      },
    });

    return res.json({ subLabel: updated });
  } catch (err: any) {
    return res.status(500).json({ error: "Could not update sub-label", details: err.message });
  }
});

router.patch("/users/:id/role", async (req, res) => {
  const prisma = req.prisma!;
  const actorId = req.user!.userId;
  const targetId = Number(req.params.id);
  const { role } = req.body;

  if (!["STANDARD", "MANAGEMENT"].includes(role)) return res.status(400).json({ error: "Invalid role" });

  try {
    const target = await prisma.user.findUnique({ where: { id: targetId } });
    if (!target) return res.status(404).json({ error: "Target not found" });

    if (target.role === "MANAGEMENT" && role === "STANDARD") {
      const managementCount = await prisma.user.count({ where: { role: "MANAGEMENT" } });
      if (managementCount <= 1) {
        return res.status(403).json({ error: "Cannot remove the last remaining management account" });
      }
    }

    const updated = await prisma.user.update({ where: { id: targetId }, data: { role } });

    await prisma.actionLog.create({
      data: {
        actorId,
        actionType: "ROLE_ASSIGN" as any,
        targetId,
        notes: `Role changed to ${role} by management ${actorId}`,
      },
    });

    return res.json({ user: updated });
  } catch (err: any) {
    return res.status(500).json({ error: "Could not change role", details: err.message });
  }
});

router.get("/logs", async (_req, res) => {
  const prisma = req.prisma!;
  try {
    const logs = await prisma.actionLog.findMany({ orderBy: { timestamp: "desc" }, take: 200 });
    return res.json(logs);
  } catch (err: any) {
    return res.status(500).json({ error: "Could not fetch logs", details: err.message });
  }
});

export default router;
EOF

# src/routes/public.ts
cat > "$OUTDIR/backend/src/routes/public.ts" <<'EOF'
import express from "express";
import { optionalAuthenticate } from "../middleware/auth";
const router = express.Router();

const CATEGORIES = [
  { key: "ENTERTAINMENT", label: "Entertainment" },
  { key: "KOVERIST", label: "Koverist (Solo)" },
  { key: "SVS", label: "SVS" },
  { key: "IDG", label: "Independent Group (IDG)" },
  { key: "OTHER", label: "Other" },
];

router.get("/", optionalAuthenticate, async (req, res) => {
  const prisma = req.prisma!;
  const counts = await Promise.all(
    CATEGORIES.map(async (c) => {
      const activeCount = await prisma.user.count({ where: { category: c.key as any, status: "ACTIVE" } });
      return { category: c.key, activeCount };
    })
  );
  return res.json({
    logo: "/assets/logo.png",
    mission: "KOVERIST — quiet registry & networking for performers and labels.",
    categories: CATEGORIES,
    counts,
    loggedIn: !!req.user,
  });
});

router.get("/session", optionalAuthenticate, async (req, res) => {
  const prisma = req.prisma!;
  if (!req.user) return res.json({ loggedIn: false });
  const userId = req.user.userId;
  const user = await prisma.user.findUnique({ where: { id: userId }, select: { id: true, username: true, role: true, status: true } });
  if (!user) return res.json({ loggedIn: false });
  return res.json({ loggedIn: true, user });
});

router.get("/categories", async (_req, res) => {
  return res.json({ categories: CATEGORIES });
});

router.get("/categories/:category", async (req, res) => {
  const prisma = req.prisma!;
  const category = (req.params.category || "").toUpperCase();
  const page = Math.max(1, Number(req.query.page) || 1);
  const perPage = Math.min(50, Number(req.query.perPage) || 20);
  const showFrozen = req.query.showFrozen === "true" || req.query.showFrozen === "1";

  if (!["ENTERTAINMENT", "KOVERIST", "SVS", "IDG", "OTHER"].includes(category)) {
    return res.status(400).json({ error: "Invalid category" });
  }

  const statuses = showFrozen ? ["ACTIVE", "FROZEN"] : ["ACTIVE"];

  const users = await prisma.user.findMany({
    where: { category: category as any, status: { in: statuses as any } },
    include: { card: true },
    skip: (page - 1) * perPage,
    take: perPage,
    orderBy: { joinDate: "desc" },
  });

  const results = users.map((u) => ({
    userId: u.id,
    username: u.username,
    category: u.category,
    status: u.status,
    joinDate: u.joinDate,
    card: u.card,
  }));

  return res.json({ category, page, perPage, results });
});

router.get("/search", async (req, res) => {
  const prisma = req.prisma!;
  const q = (req.query.q || "").toString().trim();
  const category = (req.query.category || "").toString().toUpperCase();
  const status = (req.query.status || "").toString().toUpperCase();
  const page = Math.max(1, Number(req.query.page) || 1);
  const perPage = Math.min(50, Number(req.query.perPage) || 20);

  const where: any = {};
  if (q) {
    where.OR = [
      { username: { contains: q, mode: "insensitive" } },
      { bio: { contains: q, mode: "insensitive" } },
    ];
  }
  if (category && ["ENTERTAINMENT", "KOVERIST", "SVS", "IDG", "OTHER"].includes(category)) {
    where.category = category;
  }
  if (status && ["ACTIVE", "FROZEN", "QUIT", "REMOVED"].includes(status)) {
    where.status = status;
  } else {
    where.status = "ACTIVE";
  }

  const users = await prisma.user.findMany({
    where,
    include: { card: true },
    skip: (page - 1) * perPage,
    take: perPage,
    orderBy: { username: "asc" },
  });

  const results = users.map((u) => ({
    userId: u.id,
    username: u.username,
    category: u.category,
    status: u.status,
    joinDate: u.joinDate,
    card: u.card,
  }));

  return res.json({ q, category: category || null, status: where.status, page, perPage, results });
});

router.get("/archive/quit", async (req, res) => {
  const prisma = req.prisma!;
  const users = await prisma.user.findMany({
    where: { status: "QUIT" },
    include: { card: true },
    orderBy: { joinDate: "desc" },
    take: 100,
  });
  const results = users.map((u) => ({
    userId: u.id,
    username: u.username,
    formerCategory: u.category,
    joinDate: u.joinDate,
    card: u.card,
  }));
  return res.json({ results });
});

router.get("/archive/removed", async (req, res) => {
  const prisma = req.prisma!;
  const users = await prisma.user.findMany({
    where: { status: "REMOVED" },
    include: { card: true },
    orderBy: { joinDate: "desc" },
    take: 100,
  });
  const results = users.map((u) => ({
    userId: u.id,
    username: u.username,
    formerCategory: u.category,
    card: u.card,
  }));
  return res.json({ results });
});

export default router;
EOF

# README + docs
cat > "$OUTDIR/backend/README.md" <<'EOF'
# KOVERIST Backend (scaffold)

See docs/PLATFORM_RULES.md for management and moderation rules.

Setup:
- Copy .env with DATABASE_URL and JWT_SECRET
- npm install
- npx prisma generate
- npx prisma migrate dev --name init
- npm run dev
EOF

mkdir -p "$OUTDIR/backend/docs"
cat > "$OUTDIR/backend/docs/PLATFORM_RULES.md" <<'EOF'
# Platform Rules & Management Tools (Developer Handoff)

See the conversation for full details. Key points:
- Management actions: change status, review reports, remove accounts, approve sub-labels, assign management role.
- All management actions are logged to ActionLog.
- Only MANAGEMENT role may call /management/* endpoints.
- No public call-out threads, no public moderation comments, no visible report counts.
EOF

# Frontend scaffold
mkdir -p "$OUTDIR/frontend/public/assets" "$OUTDIR/frontend/src/components" "$OUTDIR/frontend/src/pages" "$OUTDIR/frontend/src/services"

cat > "$OUTDIR/frontend/package.json" <<'EOF'
{
  "name": "koverist-frontend",
  "version": "0.1.0",
  "private": true,
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.12.1"
  },
  "devDependencies": {
    "typescript": "^5.1.6",
    "vite": "^5.2.0",
    "@types/react": "^18.2.21",
    "@types/react-dom": "^18.2.7"
  }
}
EOF

# index.html
cat > "$OUTDIR/frontend/index.html" <<'EOF'
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <link rel="icon" href="/assets/favicon.ico" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="theme-color" content="#80c342" />
    <title>KOVERIST</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
EOF

# frontend src/main.tsx
cat > "$OUTDIR/frontend/src/main.tsx" <<'EOF'
import React from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import "./styles.css";
import { initTheme } from "./theme";

initTheme();

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
);
EOF

# frontend src/App.tsx
cat > "$OUTDIR/frontend/src/App.tsx" <<'EOF'
import React, { useEffect, useState } from "react";
import { Routes, Route, useNavigate } from "react-router-dom";
import Landing from "./pages/Landing";
import Signup from "./pages/Signup";
import Login from "./pages/Login";
import Categories from "./pages/Categories";
import CategoryPage from "./pages/CategoryPage";
import CardPage from "./pages/CardPage";
import Archive from "./pages/Archive";
import { getSession } from "./services/api";
import Header from "./components/Header";

export default function App() {
  const [checking, setChecking] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    getSession()
      .then((res) => {
        if (res?.loggedIn && res.user?.status === "ACTIVE") {
          // optional redirect to dashboard
        }
      })
      .catch(() => {})
      .finally(() => setChecking(false));
  }, [navigate]);

  if (checking) return <div className="loading">Loading…</div>;

  return (
    <div className="app-root">
      <Header />
      <main className="content">
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/signup" element={<Signup />} />
          <Route path="/login" element={<Login />} />
          <Route path="/categories" element={<Categories />} />
          <Route path="/categories/:category" element={<CategoryPage />} />
          <Route path="/cards/:id" element={<CardPage />} />
          <Route path="/archive/quit" element={<Archive type="QUIT" />} />
          <Route path="/archive/removed" element={<Archive type="REMOVED" />} />
          <Route path="*" element={<div className="not-found"><h2>404 — Page not found</h2></div>} />
        </Routes>
      </main>
    </div>
  );
}
EOF

# frontend src/services/api.ts
cat > "$OUTDIR/frontend/src/services/api.ts" <<'EOF'
const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:4000";

export async function getSession() {
  try {
    const res = await fetch(`${API_BASE}/session`, { credentials: "include" });
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    return null;
  }
}

export async function signup(payload) {
  const res = await fetch(`${API_BASE}/auth/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  return res.json();
}

export async function login(payload) {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: payload.emailOrUsername, password: payload.password }),
  });
  return res.json();
}

export async function fetchCategories() {
  const res = await fetch(`${API_BASE}/categories`);
  return res.json();
}

export async function fetchCategoryPage(category, page = 1, perPage = 20, showFrozen = false) {
  const url = new URL(`${API_BASE}/categories/${category}`);
  url.searchParams.set("page", String(page));
  url.searchParams.set("perPage", String(perPage));
  if (showFrozen) url.searchParams.set("showFrozen", "1");
  const res = await fetch(url.toString());
  return res.json();
}

export async function fetchCard(id) {
  const res = await fetch(`${API_BASE}/cards/${id}`);
  return res.json();
}

export async function fetchArchive(type) {
  const url = `${API_BASE}/archive/${type === "QUIT" ? "quit" : "removed"}`;
  const res = await fetch(url);
  return res.json();
}
EOF

# frontend components Header.tsx (with animated crossfade)
cat > "$OUTDIR/frontend/src/components/Header.tsx" <<'EOF'
import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { initTheme, toggleTheme, getTheme } from "../theme";

export default function Header() {
  const [theme, setTheme] = useState("light");
  const [hasDarkLogo, setHasDarkLogo] = useState(null);

  useEffect(() => {
    initTheme();
    setTheme(getTheme());
    const onPrefChange = () => setTheme(getTheme());
    window.addEventListener("storage", onPrefChange);
    const img = new Image();
    img.src = "/assets/logo-dark.png";
    img.onload = () => setHasDarkLogo(true);
    img.onerror = () => setHasDarkLogo(false);
    return () => {
      window.removeEventListener("storage", onPrefChange);
    };
  }, []);

  function onToggle() {
    const next = toggleTheme();
    setTheme(next);
  }

  const darkLogoSrc = hasDarkLogo ? "/assets/logo-dark.png" : "/assets/logo.png";

  return (
    <header className="site-header" role="banner">
      <div className="header-inner">
        <Link to="/" className="logo" aria-label="KOVERIST home">
          <div className="logo-stack" aria-hidden="false">
            <img src="/assets/logo.png" alt="KOVERIST logo (light)" className="logo-img logo-light" width={56} height={56} />
            <img src={darkLogoSrc} alt="KOVERIST logo (dark)" className={`logo-img logo-dark ${hasDarkLogo === false ? "filter-dark" : ""}`} width={56} height={56} />
          </div>
          <div className="logo-text">KOVERIST</div>
        </Link>

        <nav className="nav" aria-label="Main navigation">
          <Link to="/categories">Categories</Link>
          <Link to="/categories/ENTERTAINMENT">Explore</Link>
          <Link to="/archive/quit">Quit Archive</Link>
          <Link to="/archive/removed">Removed</Link>

          <button className="btn small theme-toggle" onClick={onToggle} title="Toggle theme" aria-pressed={theme === "dark"}>
            {theme === "dark" ? "🌞" : "🌙"}
          </button>

          <Link to="/login" className="btn small">Log In</Link>
          <Link to="/signup" className="btn small primary">Sign Up</Link>
        </nav>
      </div>
    </header>
  );
}
EOF

# frontend components CardGrid.tsx
cat > "$OUTDIR/frontend/src/components/CardGrid.tsx" <<'EOF'
import React from "react";
import { Link } from "react-router-dom";

export default function CardGrid({ items }) {
  if (!items || items.length === 0) return <div className="empty">No cards yet</div>;
  return (
    <div className="card-grid">
      {items.map((i) => (
        <article key={i.userId} className="card-tile">
          <div className="card-preview-wrap">
            <div className="card-img" style={{ backgroundImage: i.card?.elements?.background ? `url(${i.card.elements.background})` : undefined }}>
              <div className="badge category">{String(i.category).toLowerCase()}</div>
              <div className="badge status">{String(i.status).toLowerCase()}</div>
            </div>
            <div className="card-meta">
              <h4 className="card-title">{i.username}</h4>
              <div className="card-sub">Joined {new Date(i.joinDate).toLocaleDateString()}</div>
              <Link to={`/cards/${i.card?.id ?? i.userId}`} className="view-link">View Card</Link>
            </div>
          </div>
        </article>
      ))}
    </div>
  );
}
EOF

# frontend theme.ts
cat > "$OUTDIR/frontend/src/theme.ts" <<'EOF'
export type Theme = "light" | "dark";
const STORAGE_KEY = "koverist:theme";

function prefersDark(): boolean {
  return typeof window !== "undefined" && window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
}

export function applyTheme(theme: Theme) {
  if (typeof document !== "undefined") {
    document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch (e) {}
    const meta = document.querySelector('meta[name="theme-color"]') as HTMLMetaElement | null;
    if (meta) {
      meta.content = theme === "dark" ? "#0b1417" : "#80c342";
    }
  }
}

export function initTheme() {
  if (typeof window === "undefined") return;
  let theme: Theme | null = null;
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === "light" || stored === "dark") theme = stored;
  } catch (e) {}
  if (!theme) theme = prefersDark() ? "dark" : "light";
  applyTheme(theme);
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored && window.matchMedia) {
      window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", (e) => {
        applyTheme(e.matches ? "dark" : "light");
      });
    }
  } catch (e) {}
}

export function toggleTheme(): Theme {
  const current = (document.documentElement.getAttribute("data-theme") as Theme) || "light";
  const next: Theme = current === "light" ? "dark" : "light";
  applyTheme(next);
  return next;
}

export function getTheme(): Theme {
  return (document.documentElement.getAttribute("data-theme") as Theme) || "light";
}
EOF

# frontend pages
cat > "$OUTDIR/frontend/src/pages/Landing.tsx" <<'EOF'
import React from "react";
import { Link } from "react-router-dom";

export default function Landing() {
  return (
    <div className="landing">
      <section className="hero">
        <div className="hero-media" />
        <div className="hero-content">
          <small className="hero-kicker">My Sunny Dawn</small>
          <h1 className="hero-title">KOVERIST — Quiet registry for performers</h1>
          <p className="hero-sub">Identity-first. Minimal public interaction. Connect and discover.</p>
          <div className="hero-actions">
            <Link to="/login" className="btn">Log In</Link>
            <Link to="/signup" className="btn primary">Sign Up</Link>
          </div>
          <div className="hero-nav">
            <Link to="/categories">Categories</Link>
            <Link to="/search">Search Cards</Link>
            <Link to="/archive/quit">Quit Archive</Link>
            <Link to="/archive/removed">Removed Archive</Link>
          </div>
        </div>
      </section>

      <section className="intro-cards">
        <div className="intro-left">
          <h2>Beginning of <span className="accent">Spring</span></h2>
          <p className="muted">Identity-first registry — create your KOVERIST card to be discoverable. Cards are public and visible even if account status changes.</p>
        </div>
        <div className="intro-right">
          <div className="sample-cards">
            <div className="sample-card sample-large" />
            <div className="sample-stack">
              <div className="sample-card sample-small" />
              <div className="sample-card sample-small" />
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
EOF

cat > "$OUTDIR/frontend/src/pages/Signup.tsx" <<'EOF'
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { signup } from "../services/api";

export default function Signup() {
  const [form, setForm] = useState({ username: "", email: "", password: "", category: "ENTERTAINMENT" });
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  function update(field, value) {
    setForm({ ...form, [field]: value });
  }

  async function submit(e) {
    e.preventDefault();
    setError(null);
    if (form.password.length < 8) return setError("Password must be at least 8 characters.");
    setLoading(true);
    try {
      const res = await signup(form);
      if (res?.token) {
        localStorage.setItem("token", res.token);
        navigate("/card/create");
      } else {
        setError(res.error || "Signup failed");
      }
    } catch (err) {
      setError(err.message || "Signup error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="auth-page auth-signup">
      <h2>Create an account</h2>
      <form onSubmit={submit} className="auth-form">
        <label>Username<input value={form.username} onChange={(e) => update("username", e.target.value)} required /></label>
        <label>Email<input type="email" value={form.email} onChange={(e) => update("email", e.target.value)} required /></label>
        <label>Password<input type="password" value={form.password} onChange={(e) => update("password", e.target.value)} required /></label>
        <label>Category
          <select value={form.category} onChange={(e) => update("category", e.target.value)}>
            <option value="ENTERTAINMENT">Entertainment</option>
            <option value="KOVERIST">Koverist (Solo)</option>
            <option value="SVS">SVS</option>
            <option value="IDG">Independent Group (IDG)</option>
            <option value="OTHER">Other</option>
          </select>
        </label>
        {error && <div className="form-error">{error}</div>}
        <div className="form-actions">
          <button className="btn primary" type="submit" disabled={loading}>{loading ? "Creating…" : "Create account"}</button>
        </div>
      </form>
    </div>
  );
}
EOF

cat > "$OUTDIR/frontend/src/pages/Login.tsx" <<'EOF'
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { login } from "../services/api";

export default function Login() {
  const [form, setForm] = useState({ emailOrUsername: "", password: "" });
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  function update(field, value) {
    setForm({ ...form, [field]: value });
  }

  async function submit(e) {
    e.preventDefault();
    setError(null);
    try {
      const res = await login(form);
      if (res?.token) {
        localStorage.setItem("token", res.token);
        const status = res.user?.status;
        if (status === "ACTIVE") navigate("/dashboard");
        else if (status === "FROZEN") navigate("/account/frozen");
        else navigate("/access-denied");
      } else {
        setError(res.error || "Login failed");
      }
    } catch (err) {
      setError(err.message || "Login error");
    }
  }

  return (
    <div className="auth-page auth-login">
      <h2>Log in</h2>
      <form onSubmit={submit} className="auth-form">
        <label>Email or Username<input value={form.emailOrUsername} onChange={(e) => update("emailOrUsername", e.target.value)} required /></label>
        <label>Password<input type="password" value={form.password} onChange={(e) => update("password", e.target.value)} required /></label>
        {error && <div className="form-error">{error}</div>}
        <div className="form-actions">
          <button className="btn" type="submit">Log In</button>
        </div>
      </form>
    </div>
  );
}
EOF

cat > "$OUTDIR/frontend/src/pages/Categories.tsx" <<'EOF'
import React, { useEffect, useState } from "react";
import { fetchCategories } from "../services/api";
import { Link } from "react-router-dom";

export default function Categories() {
  const [categories, setCategories] = useState([]);

  useEffect(() => {
    fetchCategories().then((res) => {
      if (res?.categories) setCategories(res.categories);
    });
  }, []);

  return (
    <div className="page categories-page">
      <h2>Categories</h2>
      <div className="categories-grid">
        {categories.map((c) => (
          <Link to={`/categories/${c.key}`} key={c.key} className="category-card">
            <div className="category-name">{c.label}</div>
            <div className="category-key">{c.key}</div>
          </Link>
        ))}
      </div>
    </div>
  );
}
EOF

cat > "$OUTDIR/frontend/src/pages/CategoryPage.tsx" <<'EOF'
import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import CardGrid from "../components/CardGrid";
import { fetchCategoryPage } from "../services/api";

export default function CategoryPage() {
  const { category } = useParams();
  const [items, setItems] = useState([]);
  const [showFrozen, setShowFrozen] = useState(false);

  useEffect(() => {
    if (!category) return;
    fetchCategoryPage(category, 1, 24, showFrozen).then((res) => {
      setItems(res.results || []);
    });
  }, [category, showFrozen]);

  return (
    <div className="page category-page">
      <header className="page-header">
        <h2>{category}</h2>
        <label className="toggle">
          <input type="checkbox" checked={showFrozen} onChange={(e) => setShowFrozen(e.target.checked)} />
          Show Frozen
        </label>
      </header>
      <CardGrid items={items} />
    </div>
  );
}
EOF

cat > "$OUTDIR/frontend/src/pages/CardPage.tsx" <<'EOF'
import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { fetchCard } from "../services/api";

export default function CardPage() {
  const { id } = useParams();
  const [card, setCard] = useState(null);

  useEffect(() => {
    if (!id) return;
    fetchCard(Number(id)).then((res) => setCard(res));
  }, [id]);

  if (!card) return <div className="loading">Loading card…</div>;

  return (
    <div className="card-page">
      <div className="card-canvas" style={{ width: 1050 / 2, height: 600 / 2 }}>
        <div className="card-top-left badge category">{card?.user?.category ?? "Category"}</div>
        <div className="card-bottom-right badge status">{card?.statusLabel ?? "Active"}</div>
        <div className="card-body">
          <h3 className="card-name">{card?.userId ? `User ${card.userId}` : "Card"}</h3>
          <pre className="card-elements">{JSON.stringify(card.elements || {}, null, 2)}</pre>
        </div>
      </div>
    </div>
  );
}
EOF

cat > "$OUTDIR/frontend/src/pages/Archive.tsx" <<'EOF'
import React, { useEffect, useState } from "react";
import { fetchArchive } from "../services/api";
import CardGrid from "../components/CardGrid";

export default function Archive({ type }) {
  const [items, setItems] = useState([]);
  useEffect(() => {
    fetchArchive(type).then((res) => setItems(res.results || []));
  }, [type]);
  return (
    <div className="page archive-page">
      <h2 className="muted">{type === "QUIT" ? "Quit Archive" : "Removed (Policy Violation)"}</h2>
      <CardGrid items={items} />
    </div>
  );
}
EOF

# frontend styles.css
cat > "$OUTDIR/frontend/src/styles.css" <<'EOF'
:root{
  --bg: #f6f8fb;
  --card-bg: #fff;
  --muted: #7b8a94;
  --accent: #80c342;
  --accent-2: #53a9d9;
  --text: #17323a;
  --radius-lg: 36px;
  --radius-md: 18px;
  --shadow: 0 8px 30px rgba(20,30,40,0.06);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
  color: var(--text);
}

body, html, #root { height: 100%; margin: 0; background: linear-gradient(180deg, var(--bg), #fff 50%); }
.app-root { min-height: 100vh; display: flex; flex-direction: column; }
.site-header { backdrop-filter: blur(6px); position: sticky; top: 0; z-index: 40; background: rgba(255,255,255,0.6); border-bottom: 1px solid rgba(20,30,40,0.03); }
.header-inner { max-width: 1100px; margin: 0 auto; padding: 14px 20px; display:flex; align-items:center; justify-content:space-between; }
.logo { display:flex; align-items:center; text-decoration:none; color:inherit; gap:12px; }
.logo-stack { width: 56px; height: 56px; position: relative; display: inline-block; border-radius: 12px; overflow: hidden; }
.logo-img { position: absolute; inset: 0; width: 100%; height: 100%; object-fit: contain; display: block; transition: opacity 360ms cubic-bezier(.2,.9,.2,1), transform 360ms cubic-bezier(.2,.9,.2,1), filter 360ms ease; padding: 6px; box-sizing: border-box; }
.logo-light { opacity: 1; transform: scale(1); z-index: 1; box-shadow: 0 8px 18px rgba(10,18,24,0.06); background: linear-gradient(180deg, rgba(255,255,255,0.06), rgba(255,255,255,0.02)); }
.logo-dark { opacity: 0; transform: scale(0.98); z-index: 0; }
[data-theme="dark"] .logo-light { opacity: 0; transform: scale(0.98); z-index: 0; }
[data-theme="dark"] .logo-dark { opacity: 1; transform: scale(1); z-index: 1; box-shadow: 0 8px 22px rgba(0,0,0,0.45); }
.logo-text { font-weight:700; letter-spacing:1px; font-size:14px; margin-left:12px; }
.nav { display:flex; gap:12px; align-items:center; }
.nav a { color:var(--muted); text-decoration:none; padding:6px 8px; border-radius:10px; }
.btn { padding:8px 14px; border-radius:12px; background:transparent; border:1px solid rgba(0,0,0,0.06); cursor:pointer; color:var(--muted); }
.btn.primary { background: var(--accent); color:#fff; border: none; }
.btn.small { padding:6px 10px; font-size:14px; }

.hero { display:flex; align-items:center; justify-content:center; max-width:1100px; margin:28px auto; gap:28px; padding:28px 18px; }
.hero-media { flex:1; height:300px; border-radius:var(--radius-lg); background-image: url('https://images.unsplash.com/photo-1508214751196-bcfd4ca60f91?q=80&w=1500&auto=format&fit=crop&ixlib=rb-4.0.3&s=4e6f6e8458cbf6e9e2b0a7d1f2d6e3a9'); background-size:cover; background-position:center; box-shadow:var(--shadow); }
.hero-content { flex:1; padding:24px; }
.hero-kicker { font-weight:600; color:var(--accent-2); font-size:14px; display:inline-block; background:rgba(83,169,217,0.08); padding:6px 10px; border-radius:12px; }
.hero-title { margin:12px 0 8px; font-size:32px; }
.hero-sub { color:var(--muted); margin-bottom:14px; }
.hero-actions { display:flex; gap:10px; margin-bottom:10px; }
.hero-nav { display:flex; gap:12px; margin-top:12px; color:var(--muted); }

.intro-cards { max-width:1100px; margin:20px auto; display:flex; gap:24px; padding:20px; }
.intro-left { flex:1; }
.intro-right { flex:1; display:flex; align-items:center; justify-content:center; }
.sample-cards { display:flex; gap:12px; align-items:center; }
.sample-large { width:320px; height:180px; border-radius:28px; background:#fff; box-shadow:var(--shadow); }
.sample-stack { display:flex; flex-direction:column; gap:12px; }
.sample-small { width:140px; height:80px; border-radius:20px; background:#fff; box-shadow:var(--shadow); }

.content { max-width:1100px; margin:0 auto; width:100%; padding:12px; }
.page { background:transparent; padding:20px 0; }
.page-header { display:flex; justify-content:space-between; align-items:center; gap:12px; margin-bottom:12px; }
.muted { color:var(--muted); }

.card-grid { display:grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap:18px; }
.card-tile { background:var(--card-bg); border-radius:18px; box-shadow:var(--shadow); overflow:hidden; padding:12px; }
.card-img { height:120px; background:linear-gradient(120deg,#eaf7f1,#f0fbff); border-radius:12px; position:relative; background-size:cover; background-position:center; }
.badge { position:absolute; padding:6px 10px; border-radius:999px; font-size:12px; color:#fff; }
.badge.category { left:12px; top:12px; background:var(--accent-2); }
.badge.status { right:12px; bottom:12px; background:var(--accent); }
.card-meta { padding-top:10px; }
.card-title { margin:0; font-size:16px; }
.card-sub { color:var(--muted); font-size:13px; margin-top:6px; }
.view-link { display:inline-block; margin-top:10px; text-decoration:none; color:var(--accent-2); font-weight:600; }

.auth-page { max-width:520px; margin:40px auto; background:var(--card-bg); padding:28px; border-radius:24px; box-shadow:var(--shadow); }
.auth-form { display:flex; flex-direction:column; gap:12px; }
.auth-form label { display:flex; flex-direction:column; gap:6px; font-size:14px; color:var(--muted); }
.auth-form input, .auth-form select { padding:10px; border-radius:12px; border:1px solid rgba(20,30,40,0.06); }
.form-actions { display:flex; justify-content:flex-end; margin-top:6px; }
.form-error { color:#c34141; }

.card-page { display:flex; justify-content:center; padding:28px 0; }
.card-canvas { background:var(--card-bg); border-radius:20px; box-shadow:var(--shadow); position:relative; padding:18px; display:flex; align-items:center; justify-content:center; }
.card-body { text-align:center; }

.loading { text-align:center; padding:40px; color:var(--muted); }
.not-found { text-align:center; padding:40px; color:var(--muted); }

@media (max-width: 800px) {
  .hero { flex-direction:column; padding:16px; }
  .intro-cards { flex-direction:column; }
  .header-inner { padding:10px; }
}
EOF

# placeholder logo (tiny base64 -> file)
cat > "$OUTDIR/frontend/public/assets/logo.png" <<'EOF'
iVBORw0KGgoAAAANSUhEUgAAAEAAAAAQCAYAAAD9Qm/sAAAAJElEQVR4nO3BMQEAAADCoPVPbQhPoAAAAAAAAAAAAAAAAAAAAAAA4GkGogAABX6JXWkAAAAAElFTkSuQmCC
EOF

# frontend README
cat > "$OUTDIR/frontend/README.md" <<'EOF'
KOVERIST Frontend scaffold (Vite + React)

- Replace public/assets/logo.png with your actual logo image.
- Run: npm install && npm run dev
- Set VITE_API_BASE in .env if backend is running elsewhere.
EOF

# Tests: jest config & tests (backend unit-level)
cat > "$OUTDIR/backend/jest.config.cjs" <<'EOF'
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  testTimeout: 10000,
  setupFilesAfterEnv: ["<rootDir>/tests/jest.setup.ts"],
};
EOF

mkdir -p "$OUTDIR/backend/tests"
cat > "$OUTDIR/backend/tests/jest.setup.ts" <<'EOF'
jest.setTimeout(20000);
EOF

cat > "$OUTDIR/backend/tests/management.test.ts" <<'EOF'
import { canDemoteManagement } from "../src/utils/management";
import { PrismaClient } from "@prisma/client";

jest.mock("@prisma/client", () => {
  const original = jest.requireActual("@prisma/client");
  const mockPrisma = new original.PrismaClient();
  return {
    PrismaClient: jest.fn(() => mockPrisma),
  };
});

describe("Management safety checks", () => {
  const prisma = new PrismaClient();

  afterAll(async () => {
    try { await prisma.$disconnect(); } catch(e) {}
  });

  test("canDemoteManagement returns true if target not management", async () => {
    (prisma.user.findUnique as any) = jest.fn().mockResolvedValue({ id: 1, role: "STANDARD" });
    const result = await canDemoteManagement(1);
    expect(result).toBe(true);
  });

  test("canDemoteManagement returns false if only one management", async () => {
    (prisma.user.findUnique as any) = jest.fn().mockResolvedValue({ id: 2, role: "MANAGEMENT" });
    (prisma.user.count as any) = jest.fn().mockResolvedValue(1);
    const result = await canDemoteManagement(2);
    expect(result).toBe(false);
  });

  test("canDemoteManagement returns true if more than one management exists", async () => {
    (prisma.user.findUnique as any) = jest.fn().mockResolvedValue({ id: 3, role: "MANAGEMENT" });
    (prisma.user.count as any) = jest.fn().mockResolvedValue(2);
    const result = await canDemoteManagement(3);
    expect(result).toBe(true);
  });
});
EOF

# Zip it
cd "$OUTDIR"
zip -r "../$ZIPNAME" ./*
cd ..

echo "Created $OUTDIR and zipped to $ZIPNAME"
echo "Done. Extract $ZIPNAME to inspect files."