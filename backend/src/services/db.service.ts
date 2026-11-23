import prisma from "../lib/prisma.js";
import type { DeploymentStatus } from "../generated/prisma/client.js";

// ---------- Shared "what fields do we return" lists ----------

const userSelect = {
  id: true,
  email: true,
  name: true,
  emailVerifiedAt: true,
  createdAt: true,
  updatedAt: true,
} as const;

const projectSelect = {
  id: true,
  repositoryUrl: true,
  name: true,
  branch: true,
  dockerfilePath: true,
  userId: true,
  createdAt: true,
  updatedAt: true,
} as const;

const deploymentSelect = {
  id: true,
  commitSha: true,
  status: true,
  projectId: true,
  containerId: true,
  createdAt: true,
  updatedAt: true,
  startedAt: true,
  stoppedAt: true,
} as const;

// ---------- Payload types ----------

export interface CreateUserPayload {
  email: string;
  passwordHash: string;
  name?: string;
}

export interface UserIdPayload {
  userId: string;
}

export interface EmailPayload {
  email: string;
}

export interface TokenHashPayload {
  tokenHash: string;
}

export interface CreateProjectPayload {
  repositoryUrl: string;
  name: string;
  branch: string;
  userId: string;
  dockerfilePath: string;
}

export interface ProjectIdPayload {
  projectId: string;
}

export interface CreateDeploymentPayload {
  commitSha: string;
  projectId: string;
  userId: string;
}

export interface DeploymentIdPayload {
  deploymentId: string;
}

// ---------- USER ----------

export const createUser = async (payload: CreateUserPayload) => {
  const { email, passwordHash, name } = payload;

  try {
    const user = await prisma.user.create({
      data: { email, passwordHash, ...(name ? { name } : {}) },
      select: userSelect,
    });

    return { success: true, user };
  } catch (error: any) {
    if (error.code === "P2002") {
      return {
        success: false,
        message: "A user with this email already exists",
      };
    }
    throw error;
  }
};

export const getUserById = async ({ userId }: UserIdPayload) => {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: userSelect,
  });

  return { success: true, user };
};

export const getUserByEmail = async ({ email }: EmailPayload) => {
  const user = await prisma.user.findUnique({
    where: { email },
    select: userSelect,
  });

  return { success: true, user };
};

export const getUserForAuthentication = async ({ email }: EmailPayload) => {
  const user = await prisma.user.findUnique({
    where: { email },
    select: { ...userSelect, passwordHash: true },
  });

  return { success: true, user };
};

export const markEmailVerified = async ({ userId }: UserIdPayload) => {
  // Only fills it in if it's still empty, so the original date is kept.
  await prisma.user.updateMany({
    where: { id: userId, emailVerifiedAt: null },
    data: { emailVerifiedAt: new Date() },
  });

  return { success: true };
};

// ---------- SESSION ----------

export const createSession = async ({
  userId,
  expiryDate,
  tokenHash,
}: {
  userId: string;
  expiryDate: Date;
  tokenHash: string;
}) => {
  const session = await prisma.session.create({
    data: { userId, tokenHash, expiresAt: expiryDate },
    include: {
      user: {
        select: { id: true, name: true, email: true, emailVerifiedAt: true },
      },
    },
  });

  return { success: true, session };
};

export const getSessionByToken = async ({ tokenHash }: TokenHashPayload) => {
  const session = await prisma.session.findUnique({
    where: { tokenHash },
    include: {
      user: {
        select: { id: true, name: true, email: true, emailVerifiedAt: true },
      },
    },
  });

  return { success: true, session };
};

export const updateSession = async ({
  tokenHash,
  revokedAt,
}: TokenHashPayload & { revokedAt: Date }) => {
  try {
    await prisma.session.update({
      where: { tokenHash },
      data: { revokedAt },
    });

    return { success: true, message: "Session updated successfully" };
  } catch (error: any) {
    if (error.code === "P2025") {
      return { success: false, message: "Session not found" };
    }
    throw error;
  }
};

// ---------- OTP ----------

// Deletes any old code for this user and saves the new one, all or nothing.
export const replaceOtp = async ({
  userId,
  codeHash,
  expiresAt,
}: {
  userId: string;
  codeHash: string;
  expiresAt: Date;
}) => {
  await prisma.$transaction([
    prisma.otpCode.deleteMany({ where: { userId } }),
    prisma.otpCode.create({ data: { userId, codeHash, expiresAt } }),
  ]);

  return { success: true };
};

export const getLatestOtp = async ({ userId }: UserIdPayload) => {
  const otp = await prisma.otpCode.findFirst({
    where: { userId, usedAt: null },
    orderBy: { createdAt: "desc" },
  });

  return { success: true, otp };
};

// Adds 1 to the wrong-guess counter and returns the new number.
// Doing it in the database means two quick guesses can't both sneak through.
export const incrementOtpAttempts = async ({ otpId }: { otpId: string }) => {
  const otp = await prisma.otpCode.update({
    where: { id: otpId },
    data: { attempts: { increment: 1 } },
    select: { attempts: true },
  });

  return { success: true, attempts: otp.attempts };
};

// Marks the code as used. Returns false if someone else already used it.
export const consumeOtp = async ({ otpId }: { otpId: string }) => {
  const result = await prisma.otpCode.updateMany({
    where: { id: otpId, usedAt: null },
    data: { usedAt: new Date() },
  });

  return { success: result.count === 1 };
};

// ---------- PROJECT ----------

export const createProject = async (payload: CreateProjectPayload) => {
  const project = await prisma.project.create({
    data: payload,
    select: projectSelect,
  });

  return { success: true, project };
};

export const getProjectById = async ({
  projectId,
  userId,
}: ProjectIdPayload & UserIdPayload) => {
  const project = await prisma.project.findFirst({
    where: { id: projectId, userId },
    select: projectSelect,
  });

  if (!project) {
    return { success: false, message: "Project not found" };
  }

  return { success: true, project };
};

export const getUserProjects = async ({ userId }: UserIdPayload) => {
  const projects = await prisma.project.findMany({
    where: { userId },
    select: projectSelect,
    orderBy: { createdAt: "desc" },
  });

  // An empty list is a normal answer, not an error.
  return { success: true, projects };
};

export const updateProject = async ({
  projectId,
  userId,
  ...updateData
}: ProjectIdPayload &
  UserIdPayload &
  Partial<
    Pick<
      CreateProjectPayload,
      "name" | "repositoryUrl" | "branch" | "dockerfilePath"
    >
  >) => {
  try {
    const project = await prisma.project.update({
      where: { id: projectId, userId },
      data: updateData,
      select: projectSelect,
    });

    return { success: true, project };
  } catch (error: any) {
    if (error.code === "P2025") {
      return { success: false, message: "Project not found" };
    }
    throw error;
  }
};

export const deleteProject = async ({
  projectId,
  userId,
}: ProjectIdPayload & UserIdPayload) => {
  try {
    const project = await prisma.project.delete({
      where: { id: projectId, userId },
      select: projectSelect,
    });

    return { success: true, project };
  } catch (error: any) {
    if (error.code === "P2025") {
      return { success: false, message: "Project not found" };
    }
    throw error;
  }
};

// ---------- DEPLOYMENT ----------

export const createDeployment = async ({
  commitSha,
  projectId,
  userId,
}: CreateDeploymentPayload) => {
  // Make sure the project really belongs to this user.
  const project = await prisma.project.findFirst({
    where: { id: projectId, userId },
    select: { id: true },
  });

  if (!project) {
    return { success: false, message: "Project not found" };
  }

  const deployment = await prisma.deployment.create({
    data: { commitSha, projectId, userId },
    select: deploymentSelect,
  });

  return { success: true, deployment };
};

export const getDeploymentById = async ({
  deploymentId,
  userId,
}: DeploymentIdPayload & UserIdPayload) => {
  const deployment = await prisma.deployment.findFirst({
    where: { id: deploymentId, userId },
    select: deploymentSelect,
  });

  if (!deployment) {
    return { success: false, message: "Deployment not found" };
  }

  return { success: true, deployment };
};

// Used by your own build/deploy worker, so it isn't tied to a user.
export const updateDeployment = async ({
  deploymentId,
  ...updateData
}: DeploymentIdPayload &
  Partial<{
    commitSha: string;
    status: DeploymentStatus;
    containerId: string | null;
    startedAt: Date | null;
    stoppedAt: Date | null;
  }>) => {
  try {
    const deployment = await prisma.deployment.update({
      where: { id: deploymentId },
      data: updateData,
      select: deploymentSelect,
    });

    return { success: true, deployment };
  } catch (error: any) {
    if (error.code === "P2025") {
      return { success: false, message: "Deployment not found" };
    }
    throw error;
  }
};

export const getProjectDeployments = async ({
  projectId,
  userId,
}: ProjectIdPayload & UserIdPayload) => {
  const deployments = await prisma.deployment.findMany({
    where: { projectId, userId },
    select: deploymentSelect,
    orderBy: { createdAt: "desc" },
  });

  return { success: true, deployments };
};

export const getUserDeployments = async ({ userId }: UserIdPayload) => {
  const deployments = await prisma.deployment.findMany({
    where: { userId },
    select: deploymentSelect,
    orderBy: { createdAt: "desc" },
  });

  return { success: true, deployments };
};
