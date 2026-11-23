import type { Request, Response, NextFunction } from "express";
import { checkSession } from "../services/auth.service.js";

export const requireAuth = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const rawToken = req.cookies?.session;

    if (!rawToken) {
      return res.status(401).json({ message: "Not logged in" });
    }

    const result = await checkSession({ rawToken });

    if (!result.session) {
      return res.status(401).json({ message: result.message });
    }

    res.locals.user = result.session.user;
    next();
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
};
