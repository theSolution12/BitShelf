import prisma from "../lib/prisma.js";
import bcrypt from "bcrypt";
import crypto from "crypto";

export interface CreateUserPayload {
  email: string;
  password: string;
  name?: string;
}

export interface UserIdPayload {
  userId: string;
}

export interface EmailPayload {
  email: string;
}

export interface TokenPaylaod {
  rawToken: string;
}
// USER SERVICES

export const createUser = async (payload: CreateUserPayload) => {
  const { email, password, name } = payload;

  const saltRounds = 11;
  const passwordHash: string = await bcrypt.hash(password, saltRounds);

  try {
    const user = await prisma.user.create({
      data: {
        email: email,
        passwordHash: passwordHash,
        ...(name ? { name: name } : {}),
      },

      select: {
        id: true,
        email: true,
        name: true,
        emailVerifiedAt: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    return {
      success: true,
      user,
    };
  } catch (error: any) {
    if (error.code === "P2002") {
      throw new Error("A user with this email already exists");
    }
    console.error("Error creating user:", error);
    throw error;
  }
};

export const getUserById = async (payload: UserIdPayload) => {
  try {
    const { userId } = payload;

    const user = await prisma.user.findUnique({
      where: {
        id: userId,
      },
      select: {
        id: true,
        email: true,
        name: true,
        emailVerifiedAt: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!user) {
      return {
        success: false,
        message: "User not found",
      };
    }

    return {
      success: true,
      user,
    };
  } catch (error: any) {
    console.error("Error fetching user by ID:", error);
    throw error;
  }
};

export const getUserByEmail = async (payload: EmailPayload) => {
  try {
    const { email } = payload;

    const user = await prisma.user.findUnique({
      where: {
        email: email,
      },
      select: {
        id: true,
        email: true,
        name: true,
        emailVerifiedAt: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!user) {
      return {
        success: false,
        message: "User not found",
      };
    }

    return {
      success: true,
      user,
    };
  } catch (error: any) {
    console.error("Error fetching user by ID:", error);
    throw error;
  }
};

export const getUserForAuthentication = async (payload: EmailPayload) => {
  try {
    const { email } = payload;

    const user = await prisma.user.findUnique({
      where: {
        email: email,
      },
      select: {
        id: true,
        email: true,
        name: true,
        passwordHash: true,
        emailVerifiedAt: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!user) {
      return {
        success: false,
        message: "User not found",
      };
    }

    return {
      success: true,
      user,
    };
  } catch (error: any) {
    console.error("Error fetching user for authentication:", error);
    throw error;
  }
};

// SESSION SERVICES

export const createSession = async ({
  userId,
  expireInDays = 7,
}: {
  userId: string;
  expireInDays?: number;
}) => {
  try {
    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + expireInDays);

    const session = await prisma.session.create({
      data: {
        userId: userId,
        tokenHash: tokenHash,
        expiresAt: expiryDate,
      },
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
            emailVerifiedAt: true,
          },
        },
      },
    });

    return {
      success: true,
      token: rawToken,
      session,
    };
  } catch (error: any) {
    console.error("Error creating session:", error);
    throw error;
  }
};

export const getSessionByToken = async (payload: TokenPaylaod) => {
  try {
    const { rawToken } = payload;

    const tokenHash = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");
    const session = await prisma.session.findUnique({
      where: {
        tokenHash: tokenHash,
      },
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
            emailVerifiedAt: true,
          },
        },
      },
    });

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
  } catch (error: any) {
    console.error("Error fetching session by token:", error);
    throw error;
  }
};

export async function revokeSession(payload: TokenPaylaod) {
  try {
    const { rawToken } = payload;
    const tokenHash = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    const session = await prisma.session.findUnique({
      where: { tokenHash },
      select: { revokedAt: true },
    });

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

    await prisma.session.update({
      where: { tokenHash },
      data: { revokedAt: new Date() },
    });

    return {
      success: true,
      message: "Session revoked successfully",
    };
  } catch (error: any) {
    if (error.code === "P2025") {
      return {
        success: false,
        message: "Session not found",
      };
    }
    console.error("Error revoking session:", error);
    throw error;
  }
}
