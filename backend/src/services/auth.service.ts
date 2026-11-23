import bcrypt from "bcrypt";
import crypto from "crypto";
import {
  createSession,
  createUser,
  getSessionByToken,
  getUserForAuthentication,
  updateSession,
  replaceOtp,
} from "./db.service.js";
import { sendOtpEmail } from "../lib/mailer.js";

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

export const register = async (payload: RegisterPayload) => {
  const { email, password, name } = payload;
  const saltRounds = 11;
  const passwordHash: string = await bcrypt.hash(password, saltRounds);
  return await createUser({ email, passwordHash, ...(name && { name }) });
};

export const login = async (payload: LoginPayload) => {
  const { email, password } = payload;
  const { user } = await getUserForAuthentication({ email });

  if (!user) {
    return { success: false, message: "Invalid credentials" };
  }

  const isPasswordValid = await bcrypt.compare(password, user.passwordHash);

  if (!isPasswordValid) {
    return { success: false, message: "Invalid credentials" };
  }

  return { success: true, user };
};

export const sessionCreate = async (payload: SessionPayload) => {
  const { userId, expireInDays = 7 } = payload;

  const rawToken = crypto.randomBytes(32).toString("hex");
  const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");

  const expiryDate = new Date();
  expiryDate.setDate(expiryDate.getDate() + expireInDays);

  const result = await createSession({
    userId,
    expiryDate,
    tokenHash,
  });

  return {
    ...result,
    rawToken,
  };
};

export const checkSession = async (payload: TokenPayload) => {
  const { rawToken } = payload;

  const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");

  const { session } = await getSessionByToken({ tokenHash });

  if (!session) {
    return {
      success: false,
      message: "No session found",
    };
  }

  if (session.revokedAt) {
    return {
      success: false,
      message: "Session revoked",
    };
  }

  if (session.expiresAt <= new Date()) {
    return {
      success: false,
      message: "Session expired",
    };
  }

  return {
    success: true,
    session,
  };
};

export const revokeSession = async (payload: TokenPayload) => {
  const { rawToken } = payload;

  const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");

  const { session } = await getSessionByToken({ tokenHash });

  if (!session) {
    return {
      success: false,
      message: "Session not found",
    };
  }

  if (session.revokedAt) {
    return {
      success: true,
      message: "Session already revoked",
    };
  }

  const revokeDate = new Date();

  await updateSession({ tokenHash, revokedAt: revokeDate });

  return {
    success: true,
    message: "Session revoked successfully",
  };
};

const hashOtp = (userId: string, code: string) => {
  return crypto
    .createHmac("sha256", process.env.OTP_SECRET!)
    .update(`${userId}:${code}`)
    .digest("hex");
};

export const otpSend = async ({
  userId,
  email,
}: {
  userId: string;
  email: string;
}) => {
  const code = crypto.randomInt(0, 1_000_000).toString().padStart(6, "0");
  const codeHash = hashOtp(userId, code);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

  await replaceOtp({ userId, codeHash, expiresAt });
  await sendOtpEmail({ to: email, code });

  return { success: true };
};
