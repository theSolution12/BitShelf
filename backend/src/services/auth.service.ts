import bcrypt from "bcrypt";
import crypto from "crypto";
import {
  consumeOtp,
  createSession,
  createUser,
  getLatestOtp,
  getSessionByToken,
  getUserByEmail,
  getUserForAuthentication,
  incrementOtpAttempts,
  markEmailVerified,
  replaceOtp,
  updateSession,
} from "./db.service.js";
import { sendOtpEmail } from "../lib/mailer.js";
import logger from "../lib/logger.js";
import type { SafeUser, SessionWithUser } from "./db.service.js";

// ---------- Settings (change them here, in one place) ----------

const BCRYPT_ROUNDS = 11;
const OTP_TTL_MS = 10 * 60 * 1000; // a code lives 10 minutes
const OTP_MAX_ATTEMPTS = 5; // wrong guesses allowed per code
const OTP_RESEND_COOLDOWN_MS = 60 * 1000; // wait between new codes

// A fake hash, used so "no such user" takes as long as "wrong password".
const DUMMY_HASH = bcrypt.hashSync("not-a-real-password", BCRYPT_ROUNDS);

// ---------- Payload types ----------

export interface RegisterPayload {
  email: string;
  password: string;
  name?: string;
}

export interface LoginPayload {
  email: string;
  password: string;
}

export interface SessionPayload {
  userId: string;
  expireInDays?: number;
}

export interface TokenPayload {
  rawToken: string;
}

export interface OtpSendPayload {
  userId: string;
  email: string;
}

export interface OtpRequestPayload {
  email: string;
}

export interface OtpVerifyPayload {
  email: string;
  code: string;
}

// ---------- What every function in this file returns ----------
// success and message are ALWAYS there.
// The "?" fields only exist when success is true.

export interface RegisterResult {
  success: boolean;
  message: string;
  user?: SafeUser;
}

export interface LoginResult {
  success: boolean;
  message: string;
  user?: SafeUser;
}

export interface OtpSendResult {
  success: boolean;
  message: string;
}

export interface OtpRequestResult {
  success: boolean;
  message: string;
}

export interface OtpVerifyResult {
  success: boolean;
  message: string;
  user?: SafeUser;
}

export interface SessionCreateResult {
  success: boolean;
  message: string;
  session?: SessionWithUser;
  rawToken?: string;
}

export interface CheckSessionResult {
  success: boolean;
  message: string;
  session?: SessionWithUser;
}

export interface RevokeSessionResult {
  success: boolean;
  message: string;
}

// login returns this message when the email isn't verified yet.
// The controller compares against it, so it lives in one place.
export const EMAIL_NOT_VERIFIED_MESSAGE = "Email not verified";

// ---------- Small helpers ----------

const normalizeEmail = (email: string) => email.trim().toLowerCase();

const hashToken = (rawToken: string) =>
  crypto.createHash("sha256").update(rawToken).digest("hex");

// Codes are scrambled with a secret key that only lives in your .env.
const hashOtp = (userId: string, code: string) =>
  crypto
    .createHmac("sha256", process.env.OTP_SECRET!)
    .update(`${userId}:${code}`)
    .digest("hex");

const safeEqual = (a: string, b: string) => {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
};

// ---------- OTP ----------

export const otpSend = async ({
  userId,
  email,
}: OtpSendPayload): Promise<OtpSendResult> => {
  // Don't let anyone spam a mailbox with codes.
  const latest = await getLatestOtp({ userId });
  if (
    latest.success &&
    latest.otp &&
    Date.now() - latest.otp.createdAt.getTime() < OTP_RESEND_COOLDOWN_MS
  ) {
    return {
      success: false,
      message: "Please wait a minute before asking for another code",
    };
  }

  const code = crypto.randomInt(0, 1_000_000).toString().padStart(6, "0");
  const codeHash = hashOtp(userId, code);
  const expiresAt = new Date(Date.now() + OTP_TTL_MS);

  await replaceOtp({ userId, codeHash, expiresAt });
  await sendOtpEmail({ to: email, code });

  // DEV ONLY: lets you test without email. Delete once SMTP works.
  if (process.env.NODE_ENV !== "production") {
    logger.info({ code }, "DEV ONLY: otp code");
  }

  return { success: true, message: "Code sent" };
};

// For the "send me a code" button (OTP login and resend).
// Always gives the same answer, so nobody can use it to find out
// which emails have accounts.
export const otpRequest = async ({
  email,
}: OtpRequestPayload): Promise<OtpRequestResult> => {
  const found = await getUserByEmail({ email: normalizeEmail(email) });

  if (found.success && found.user) {
    await otpSend({ userId: found.user.id, email: found.user.email });
  }

  return {
    success: true,
    message: "If that email has an account, we sent a code",
  };
};

// Checks the code. A correct code proves the person owns the inbox,
// so it verifies the email (if needed) AND the controller then logs them in.
export const otpVerify = async ({
  email,
  code,
}: OtpVerifyPayload): Promise<OtpVerifyResult> => {
  // One message for every kind of failure, so attackers learn nothing.
  const invalid: OtpVerifyResult = {
    success: false,
    message: "Invalid or expired code",
  };

  const found = await getUserByEmail({ email: normalizeEmail(email) });
  if (!found.success || !found.user) return invalid;
  const user = found.user;

  const latest = await getLatestOtp({ userId: user.id });
  if (!latest.success || !latest.otp) return invalid;
  const otp = latest.otp;

  if (otp.expiresAt <= new Date()) return invalid;

  // Count this guess first, then check. Counting first means even
  // many quick guesses at once can't beat the limit.
  const counted = await incrementOtpAttempts({ otpId: otp.id });
  if (!counted.success || counted.attempts === undefined) return invalid;
  if (counted.attempts > OTP_MAX_ATTEMPTS) return invalid;

  if (!safeEqual(hashOtp(user.id, code), otp.codeHash)) return invalid;

  // Use it up. If someone else used it a split second ago, this fails.
  const consumed = await consumeOtp({ otpId: otp.id });
  if (!consumed.success) return invalid;

  if (!user.emailVerifiedAt) {
    await markEmailVerified({ userId: user.id });
  }

  return {
    success: true,
    message: "Code verified",
    user: { ...user, emailVerifiedAt: user.emailVerifiedAt ?? new Date() },
  };
};

// ---------- Register / Login ----------

export const register = async (
  payload: RegisterPayload,
): Promise<RegisterResult> => {
  const { password, name } = payload;
  const email = normalizeEmail(payload.email);

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const created = await createUser({
    email,
    passwordHash,
    ...(name && { name }),
  });

  if (!created.success || !created.user) {
    return { success: false, message: created.message };
  }

  await otpSend({ userId: created.user.id, email: created.user.email });

  return {
    success: true,
    message: "Account created. Check your email for a code",
    user: created.user,
  };
};

export const login = async (payload: LoginPayload): Promise<LoginResult> => {
  const { password } = payload;
  const email = normalizeEmail(payload.email);

  const found = await getUserForAuthentication({ email });
  const user = found.success ? found.user : undefined;

  // Always run bcrypt, even when there's no user, so the response
  // time doesn't give away which emails exist.
  const isPasswordValid = await bcrypt.compare(
    password,
    user?.passwordHash ?? DUMMY_HASH,
  );

  if (!user || !isPasswordValid) {
    return { success: false, message: "Invalid credentials" };
  }

  if (!user.emailVerifiedAt) {
    // Send a fresh code automatically. If it's too soon for another,
    // the earlier one is still valid, so we ignore that result.
    await otpSend({ userId: user.id, email: user.email });

    return { success: false, message: EMAIL_NOT_VERIFIED_MESSAGE };
  }

  // Never hand the password hash back to the controller.
  const { passwordHash: _passwordHash, ...safeUser } = user;

  return { success: true, message: "Login successful", user: safeUser };
};

// ---------- Sessions ----------

export const sessionCreate = async (
  payload: SessionPayload,
): Promise<SessionCreateResult> => {
  const { userId, expireInDays = 7 } = payload;

  const rawToken = crypto.randomBytes(32).toString("hex");
  const tokenHash = hashToken(rawToken);

  const expiryDate = new Date(Date.now() + expireInDays * 24 * 60 * 60 * 1000);

  const created = await createSession({ userId, expiryDate, tokenHash });

  if (!created.success || !created.session) {
    return { success: false, message: created.message };
  }

  return {
    success: true,
    message: "Session created",
    session: created.session,
    rawToken,
  };
};

export const checkSession = async ({
  rawToken,
}: TokenPayload): Promise<CheckSessionResult> => {
  const found = await getSessionByToken({ tokenHash: hashToken(rawToken) });

  if (!found.success || !found.session) {
    return { success: false, message: "No session found" };
  }
  const session = found.session;

  if (session.revokedAt) return { success: false, message: "Session revoked" };

  if (session.expiresAt <= new Date()) {
    return { success: false, message: "Session expired" };
  }

  return { success: true, message: "Session valid", session };
};

export const revokeSession = async ({
  rawToken,
}: TokenPayload): Promise<RevokeSessionResult> => {
  const tokenHash = hashToken(rawToken);

  const found = await getSessionByToken({ tokenHash });
  if (!found.success || !found.session) {
    return { success: false, message: "Session not found" };
  }

  if (found.session.revokedAt) {
    return { success: true, message: "Session already revoked" };
  }

  const updated = await updateSession({ tokenHash, revokedAt: new Date() });
  if (!updated.success) return { success: false, message: updated.message };

  return { success: true, message: "Session revoked successfully" };
};
