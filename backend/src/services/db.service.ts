import prisma from "../lib/prisma.js";
import type {
  User,
  Session,
  Project,
  OtpCode,
  DeploymentStatus,
} from "../generated/prisma/client.js";

// ---------- What the data looks like ----------

// A user WITHOUT the password hash. This is what we normally return.
export interface SafeUser {
  id: string;
  email: string;
  name: string | null;
  emailVerifiedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

// A session, plus a few details about its user.
export interface SessionWithUser extends Session {
  user: {
    id: string;
    name: string | null;
    email: string;
    emailVerifiedAt: Date | null;
  };
}

// A deployment (we leave out userId).
export interface PublicDeployment {
  id: string;
  commitSha: string;
  status: DeploymentStatus;
  projectId: string;
  containerId: string | null;
  createdAt: Date;
  updatedAt: Date;
  startedAt: Date | null;
  stoppedAt: Date | null;
}

// ---------- What every function in this file returns ----------
// success and message are ALWAYS there.
// The "?" fields only exist when success is true.

export interface MessageResult {
  success: boolean;
  message: string;
}

export interface UserResult {
  success: boolean;
  message: string;
  user?: SafeUser;
}

// Includes the password hash. Only the login check uses this.
export interface AuthUserResult {
  success: boolean;
  message: string;
  user?: User;
}

export interface SessionResult {
  success: boolean;
  message: string;
  session?: SessionWithUser;
}

export interface OtpResult {
  success: boolean;
  message: string;
  otp?: OtpCode;
}

export interface AttemptsResult {
  success: boolean;
  message: string;
  attempts?: number;
}

export interface ProjectResult {
  success: boolean;
  message: string;
  project?: Project;
}

export interface ProjectsResult {
  success: boolean;
  message: string;
  projects?: Project[];
}

export interface DeploymentResult {
  success: boolean;
  message: string;
  deployment?: PublicDeployment;
}

export interface DeploymentsResult {
  success: boolean;
  message: string;
  deployments?: PublicDeployment[];
}

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

const sessionUserSelect = {
  id: true,
  name: true,
  email: true,
  emailVerifiedAt: true,
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

export const createUser = async (
  payload: CreateUserPayload,
): Promise<UserResult> => {
  const { email, passwordHash, name } = payload;

  try {
    const user = await prisma.user.create({
      data: { email, passwordHash, ...(name ? { name } : {}) },
      select: userSelect,
    });

    return { success: true, message: "User created", user };
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

export const getUserById = async ({
  userId,
}: UserIdPayload): Promise<UserResult> => {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: userSelect,
  });

  if (!user) return { success: false, message: "User not found" };

  return { success: true, message: "User found", user };
};

export const getUserByEmail = async ({
  email,
}: EmailPayload): Promise<UserResult> => {
  const user = await prisma.user.findUnique({
    where: { email },
    select: userSelect,
  });

  if (!user) return { success: false, message: "User not found" };

  return { success: true, message: "User found", user };
};

// Includes passwordHash. Only the login check should use this.
export const getUserForAuthentication = async ({
  email,
}: EmailPayload): Promise<AuthUserResult> => {
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) return { success: false, message: "User not found" };

  return { success: true, message: "User found", user };
};

export const markEmailVerified = async ({
  userId,
}: UserIdPayload): Promise<MessageResult> => {
  // Only fills it in if it's still empty, so the original date is kept.
  const result = await prisma.user.updateMany({
    where: { id: userId, emailVerifiedAt: null },
    data: { emailVerifiedAt: new Date() },
  });

  return {
    success: true,
    message: result.count === 1 ? "Email verified" : "Email already verified",
  };
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
}): Promise<SessionResult> => {
  const session = await prisma.session.create({
    data: { userId, tokenHash, expiresAt: expiryDate },
    include: { user: { select: sessionUserSelect } },
  });

  return { success: true, message: "Session created", session };
};

export const getSessionByToken = async ({
  tokenHash,
}: TokenHashPayload): Promise<SessionResult> => {
  const session = await prisma.session.findUnique({
    where: { tokenHash },
    include: { user: { select: sessionUserSelect } },
  });

  if (!session) return { success: false, message: "Session not found" };

  return { success: true, message: "Session found", session };
};

export const updateSession = async ({
  tokenHash,
  revokedAt,
}: TokenHashPayload & { revokedAt: Date }): Promise<MessageResult> => {
  try {
    await prisma.session.update({
      where: { tokenHash },
      data: { revokedAt },
    });

    return { success: true, message: "Session updated" };
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
}): Promise<MessageResult> => {
  await prisma.$transaction([
    prisma.otpCode.deleteMany({ where: { userId } }),
    prisma.otpCode.create({ data: { userId, codeHash, expiresAt } }),
  ]);

  return { success: true, message: "Code saved" };
};

export const getLatestOtp = async ({
  userId,
}: UserIdPayload): Promise<OtpResult> => {
  const otp = await prisma.otpCode.findFirst({
    where: { userId, usedAt: null },
    orderBy: { createdAt: "desc" },
  });

  if (!otp) return { success: false, message: "No active code found" };

  return { success: true, message: "Code found", otp };
};

// Adds 1 to the wrong-guess counter and returns the new number.
// Doing it in the database means two quick guesses can't both sneak through.
export const incrementOtpAttempts = async ({
  otpId,
}: {
  otpId: string;
}): Promise<AttemptsResult> => {
  try {
    const otp = await prisma.otpCode.update({
      where: { id: otpId },
      data: { attempts: { increment: 1 } },
      select: { attempts: true },
    });

    return {
      success: true,
      message: "Attempt counted",
      attempts: otp.attempts,
    };
  } catch (error: any) {
    // The code can vanish if the user asked for a new one at the same moment.
    if (error.code === "P2025") {
      return { success: false, message: "Code not found" };
    }
    throw error;
  }
};

// Marks the code as used. Fails if someone else already used it.
export const consumeOtp = async ({
  otpId,
}: {
  otpId: string;
}): Promise<MessageResult> => {
  const result = await prisma.otpCode.updateMany({
    where: { id: otpId, usedAt: null },
    data: { usedAt: new Date() },
  });

  if (result.count !== 1) {
    return { success: false, message: "Code already used" };
  }

  return { success: true, message: "Code used" };
};

// ---------- PROJECT ----------

export const createProject = async (
  payload: CreateProjectPayload,
): Promise<ProjectResult> => {
  const project = await prisma.project.create({
    data: payload,
    select: projectSelect,
  });

  return { success: true, message: "Project created", project };
};

export const getProjectById = async ({
  projectId,
  userId,
}: ProjectIdPayload & UserIdPayload): Promise<ProjectResult> => {
  const project = await prisma.project.findFirst({
    where: { id: projectId, userId },
    select: projectSelect,
  });

  if (!project) return { success: false, message: "Project not found" };

  return { success: true, message: "Project found", project };
};

export const getUserProjects = async ({
  userId,
}: UserIdPayload): Promise<ProjectsResult> => {
  const projects = await prisma.project.findMany({
    where: { userId },
    select: projectSelect,
    orderBy: { createdAt: "desc" },
  });

  return { success: true, message: "Projects fetched", projects };
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
  >): Promise<ProjectResult> => {
  try {
    const project = await prisma.project.update({
      where: { id: projectId, userId },
      data: updateData,
      select: projectSelect,
    });

    return { success: true, message: "Project updated", project };
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
}: ProjectIdPayload & UserIdPayload): Promise<ProjectResult> => {
  try {
    const project = await prisma.project.delete({
      where: { id: projectId, userId },
      select: projectSelect,
    });

    return { success: true, message: "Project deleted", project };
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
}: CreateDeploymentPayload): Promise<DeploymentResult> => {
  // Make sure the project really belongs to this user.
  const project = await prisma.project.findFirst({
    where: { id: projectId, userId },
    select: { id: true },
  });

  if (!project) return { success: false, message: "Project not found" };

  const deployment = await prisma.deployment.create({
    data: { commitSha, projectId, userId },
    select: deploymentSelect,
  });

  return { success: true, message: "Deployment created", deployment };
};

export const getDeploymentById = async ({
  deploymentId,
  userId,
}: DeploymentIdPayload & UserIdPayload): Promise<DeploymentResult> => {
  const deployment = await prisma.deployment.findFirst({
    where: { id: deploymentId, userId },
    select: deploymentSelect,
  });

  if (!deployment) return { success: false, message: "Deployment not found" };

  return { success: true, message: "Deployment found", deployment };
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
  }>): Promise<DeploymentResult> => {
  try {
    const deployment = await prisma.deployment.update({
      where: { id: deploymentId },
      data: updateData,
      select: deploymentSelect,
    });

    return { success: true, message: "Deployment updated", deployment };
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
}: ProjectIdPayload & UserIdPayload): Promise<DeploymentsResult> => {
  const deployments = await prisma.deployment.findMany({
    where: { projectId, userId },
    select: deploymentSelect,
    orderBy: { createdAt: "desc" },
  });

  return { success: true, message: "Deployments fetched", deployments };
};

export const getUserDeployments = async ({
  userId,
}: UserIdPayload): Promise<DeploymentsResult> => {
  const deployments = await prisma.deployment.findMany({
    where: { userId },
    select: deploymentSelect,
    orderBy: { createdAt: "desc" },
  });

  return { success: true, message: "Deployments fetched", deployments };
};
