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

// ---------- Settings (change them here, in one place) ----------

const BCRYPT_ROUNDS = 11;
const OTP_TTL_MS = 10 * 60 * 1000; // a code lives 10 minutes
const OTP_MAX_ATTEMPTS = 5; // wrong guesses allowed per code
const OTP_RESEND_COOLDOWN_MS = 60 * 1000; // wait between new codes

// A fake hash, used so "no such user" takes as long as "wrong password".
const DUMMY_HASH = bcrypt.hashSync("not-a-real-password", BCRYPT_ROUNDS);

// ---------- Types ----------

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

export const otpSend = async ({ userId, email }: OtpSendPayload) => {
  // Don't let anyone spam a mailbox with codes.
  const { otp: existing } = await getLatestOtp({ userId });
  if (
    existing &&
    Date.now() - existing.createdAt.getTime() < OTP_RESEND_COOLDOWN_MS
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

  return { success: true, message: "Code sent" };
};

// For the "send me a code" button (OTP login and resend).
// Always gives the same answer, so nobody can use it to find out
// which emails have accounts.
export const otpRequest = async ({ email }: OtpRequestPayload) => {
  const { user } = await getUserByEmail({ email: normalizeEmail(email) });

  if (user) {
    await otpSend({ userId: user.id, email: user.email });
  }

  return {
    success: true,
    message: "If that email has an account, we sent a code",
  };
};

// Checks the code. A correct code proves the person owns the inbox,
// so it verifies the email (if needed) AND tells the controller to log in.
export const otpVerify = async ({ email, code }: OtpVerifyPayload) => {
  const invalid = { success: false, message: "Invalid or expired code" };

  const { user } = await getUserByEmail({ email: normalizeEmail(email) });
  if (!user) {
    return {
      success: false,
      message: "Invalid email",
    };
  }

  const { otp } = await getLatestOtp({ userId: user.id });
  if (!otp) return invalid;

  if (otp.expiresAt <= new Date()) return invalid;

  // Count this guess first, then check. Counting first means even
  // many quick guesses at once can't beat the limit.
  const { attempts } = await incrementOtpAttempts({ otpId: otp.id });
  if (attempts > OTP_MAX_ATTEMPTS) return invalid;

  if (!safeEqual(hashOtp(user.id, code), otp.codeHash)) return invalid;

  // Use it up. If someone else used it a split second ago, this fails.
  const { success: consumed } = await consumeOtp({ otpId: otp.id });
  if (!consumed) return invalid;

  if (!user.emailVerifiedAt) {
    await markEmailVerified({ userId: user.id });
  }

  return {
    success: true,
    user: { ...user, emailVerifiedAt: user.emailVerifiedAt ?? new Date() },
  };
};

// ---------- Register / Login ----------

export const register = async (payload: RegisterPayload) => {
  const { password, name } = payload;
  const email = normalizeEmail(payload.email);

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const result = await createUser({
    email,
    passwordHash,
    ...(name && { name }),
  });

  if (!result.success || !result.user) {
    return {
      success: false,
      message: result.message ?? "Could not create account",
    };
  }

  await otpSend({ userId: result.user.id, email: result.user.email });

  return {
    success: true,
    user: result.user,
    message: "Account created. Check your email for a code",
  };
};

export const login = async (payload: LoginPayload) => {
  const { password } = payload;
  const email = normalizeEmail(payload.email);

  const { user } = await getUserForAuthentication({ email });

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

    return {
      success: false,
      code: "EMAIL_NOT_VERIFIED",
      message: "Email not verified",
    };
  }

  // Never hand the password hash back to the controller.
  const { passwordHash: _passwordHash, ...safeUser } = user;

  return { success: true, user: safeUser };
};

// ---------- Sessions ----------

export const sessionCreate = async (payload: SessionPayload) => {
  const { userId, expireInDays = 7 } = payload;

  const rawToken = crypto.randomBytes(32).toString("hex");
  const tokenHash = hashToken(rawToken);

  const expiryDate = new Date(Date.now() + expireInDays * 24 * 60 * 60 * 1000);

  const result = await createSession({ userId, expiryDate, tokenHash });

  return { ...result, rawToken };
};

export const checkSession = async ({ rawToken }: TokenPayload) => {
  const { session } = await getSessionByToken({
    tokenHash: hashToken(rawToken),
  });

  if (!session) {
    return { success: false, message: "No session found" };
  }

  if (session.revokedAt) {
    return { success: false, message: "Session revoked" };
  }

  if (session.expiresAt <= new Date()) {
    return { success: false, message: "Session expired" };
  }

  return { success: true, session };
};

export const revokeSession = async ({ rawToken }: TokenPayload) => {
  const tokenHash = hashToken(rawToken);

  const { session } = await getSessionByToken({ tokenHash });

  if (!session) {
    return { success: false, message: "Session not found" };
  }

  if (session.revokedAt) {
    return { success: true, message: "Session already revoked" };
  }

  await updateSession({ tokenHash, revokedAt: new Date() });

  return { success: true, message: "Session revoked successfully" };
};
