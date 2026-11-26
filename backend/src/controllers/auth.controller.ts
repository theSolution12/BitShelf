import {
  login,
  register,
  sessionCreate,
  revokeSession,
  otpRequest,
  otpVerify,
  EMAIL_NOT_VERIFIED_MESSAGE,
} from "../services/auth.service.js";
import type { Request, Response } from "express";
import logger from "../lib/logger.js";

const SESSION_DAYS = 7;

const cookieOptions = {
  httpOnly: true, // JavaScript in the page can't read it
  secure: process.env.NODE_ENV === "production", // https only when live
  sameSite: "lax" as const, // blocks most cross-site tricks
  maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000,
};

const isText = (value: unknown): value is string =>
  typeof value === "string" && value.trim().length > 0;

// Creates the session and puts the ticket in the browser's cookie.
const startSession = async (res: Response, userId: string) => {
  const created = await sessionCreate({ userId, expireInDays: SESSION_DAYS });

  if (!created.success || !created.rawToken) {
    throw new Error(created.message);
  }

  res.cookie("session", created.rawToken, cookieOptions);
};

// Logger rule: data goes FIRST, the message goes SECOND.
//   logger.error({ err: error }, "what was happening");

export const registerController = async (req: Request, res: Response) => {
  try {
    const { email, password, name } = req.body ?? {};

    if (!isText(email) || !isText(password)) {
      return res.status(400).json({ message: "Email and password required" });
    }

    if (password.length < 8) {
      return res
        .status(400)
        .json({ message: "Password must be at least 8 characters" });
    }

    const result = await register({ email, password, name });

    if (!result.success) {
      logger.info(`registerController: ${result.message}`);
      return res.status(409).json({ message: result.message });
    }

    logger.success("registerController: registration successful");

    // No session yet. They must verify their email first.
    return res.status(201).json({
      message: result.message,
      user: result.user,
    });
  } catch (error: any) {
    logger.error({ err: error }, "registerController failed");
    return res.status(500).json({ message: "Something went wrong" });
  }
};

export const loginController = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body ?? {};

    if (!isText(email) || !isText(password)) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const result = await login({ email, password });

    if (!result.success) {
      // Status 403 tells the frontend to open the verify-email page.
      if (result.message === EMAIL_NOT_VERIFIED_MESSAGE) {
        return res.status(403).json({ message: result.message });
      }
      return res.status(401).json({ message: result.message });
    }

    if (!result.user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    await startSession(res, result.user.id);

    logger.success("loginController: login successful");
    return res.status(200).json({ message: result.message, user: result.user });
  } catch (error: any) {
    logger.error({ err: error }, "loginController failed");
    return res.status(500).json({ message: "Something went wrong" });
  }
};

// "Send me a code": used by OTP login and by the resend button.
export const otpRequestController = async (req: Request, res: Response) => {
  try {
    const { email } = req.body ?? {};

    if (!isText(email)) {
      return res.status(400).json({ message: "Email required" });
    }

    const result = await otpRequest({ email });
    return res.status(200).json({ message: result.message });
  } catch (error: any) {
    logger.error({ err: error }, "otpRequestController failed");
    return res.status(500).json({ message: "Something went wrong" });
  }
};

// The verify-email page and OTP login both end up here.
export const otpVerifyController = async (req: Request, res: Response) => {
  try {
    const { email, code } = req.body ?? {};

    if (!isText(email) || !isText(code) || !/^\d{6}$/.test(code.trim())) {
      return res
        .status(400)
        .json({ message: "Email and 6-digit code required" });
    }

    const result = await otpVerify({ email, code: code.trim() });

    if (!result.success) {
      return res.status(401).json({ message: result.message });
    }

    if (!result.user) {
      return res.status(401).json({ message: "Invalid or expired code" });
    }

    await startSession(res, result.user.id);

    logger.success("otpVerifyController: code verified");
    return res.status(200).json({ message: result.message, user: result.user });
  } catch (error: any) {
    logger.error({ err: error }, "otpVerifyController failed");
    return res.status(500).json({ message: "Something went wrong" });
  }
};

export const logoutController = async (req: Request, res: Response) => {
  try {
    const rawToken = req.cookies?.session;

    if (rawToken) {
      await revokeSession({ rawToken });
    }

    res.clearCookie("session", { ...cookieOptions, maxAge: undefined });
    return res.status(200).json({ message: "Logged out" });
  } catch (error: any) {
    logger.error({ err: error }, "logoutController failed");
    return res.status(500).json({ message: "Something went wrong" });
  }
};

// Sits behind requireAuth, which already put the user in res.locals.
export const meController = async (_req: Request, res: Response) => {
  return res.status(200).json({ user: res.locals.user });
};
