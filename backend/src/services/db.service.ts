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

// PROJECT SERVICES

export const createProject = async (payload: CreateProjectPayload) => {
  try {
    const { repositoryUrl, name, branch, userId, dockerfilePath } = payload;

    const project = await prisma.project.create({
      data: {
        repositoryUrl,
        name,
        branch,
        userId,
        dockerfilePath,
      },
      select: {
        id: true,
        repositoryUrl: true,
        name: true,
        branch: true,
        userId: true,
        projectPath: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    return {
      success: true,
      project,
    };
  } catch (error: any) {
    console.error("Error creating project:", error);
    throw error;
  }
};

export const getProjectById = async (
  payload: ProjectIdPayload & UserIdPayload,
) => {
  try {
    const { projectId, userId } = payload;

    const project = await prisma.project.findUnique({
      where: { id: projectId, userId: userId },
      select: {
        id: true,
        repositoryUrl: true,
        name: true,
        branch: true,
        userId: true,
        projectPath: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!project) {
      return {
        success: false,
        message: "Project not found",
      };
    }

    return {
      success: true,
      project,
    };
  } catch (error: any) {
    console.error("Error fetching project by ID:", error);
    throw error;
  }
};

export const getUserProjects = async (payload: UserIdPayload) => {
  try {
    const { userId } = payload;

    const projects = await prisma.project.findMany({
      where: { userId },
      select: {
        id: true,
        repositoryUrl: true,
        name: true,
        branch: true,
        userId: true,
        projectPath: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!projects || projects.length === 0) {
      return {
        success: false,
        message: "No projects found for this user",
      };
    }

    return {
      success: true,
      projects,
    };
  } catch (error: any) {
    console.error("Error fetching user projects:", error);
    throw error;
  }
};

export const updateProject = async (
  payload: ProjectIdPayload & Partial<CreateProjectPayload>,
) => {
  try {
    const { projectId, ...updateData } = payload;

    const project = await prisma.project.update({
      where: { id: projectId },
      data: updateData,
      select: {
        id: true,
        repositoryUrl: true,
        name: true,
        branch: true,
        userId: true,
        projectPath: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    return {
      success: true,
      project,
    };
  } catch (error: any) {
    console.error("Error updating project:", error);
    throw error;
  }
};

export const deleteProject = async (payload: ProjectIdPayload) => {
  try {
    const { projectId } = payload;

    const project = await prisma.project.delete({
      where: { id: projectId },
      select: {
        id: true,
        repositoryUrl: true,
        name: true,
        branch: true,
        userId: true,
        projectPath: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    return {
      success: true,
      project,
    };
  } catch (error: any) {
    console.error("Error deleting project:", error);
    throw error;
  }
};

// DEPLOYMENT SERVICES

export const createDeployment = async (payload: CreateDeploymentPayload) => {
  try {
    const { commitSha, projectId, userId } = payload;

    const deployment = await prisma.deployment.create({
      data: {
        commitSha,
        projectId,
        userId,
      },
      select: {
        id: true,
        commitSha: true,
        status: true,
        projectId: true,
        containerId: true,
        createdAt: true,
        updatedAt: true,
        startedAt: true,
        stoppedAt: true,
      },
    });

    return {
      success: true,
      deployment,
    };
  } catch (error: any) {
    console.error("Error creating deployment:", error);
    throw error;
  }
};

export const getDeploymentById = async (
  payload: DeploymentIdPayload & UserIdPayload,
) => {
  try {
    const { deploymentId, userId } = payload;

    const deployment = await prisma.deployment.findUnique({
      where: {
        id: deploymentId,
        userId: userId,
      },
      select: {
        id: true,
        commitSha: true,
        status: true,
        projectId: true,
        containerId: true,
        createdAt: true,
        updatedAt: true,
        startedAt: true,
        stoppedAt: true,
      },
    });

    if (!deployment) {
      return {
        success: false,
        message: "Deployment not found",
      };
    }

    return {
      success: true,
      deployment,
    };
  } catch (error: any) {
    console.error("Error fetching deployment:", error);
    throw error;
  }
};

export const updateDeployment = async (
  payload: DeploymentIdPayload & Partial<CreateDeploymentPayload>,
) => {
  try {
    const { deploymentId, ...updateData } = payload;

    const deployment = await prisma.deployment.update({
      where: { id: deploymentId },
      data: updateData,
      select: {
        id: true,
        commitSha: true,
        status: true,
        projectId: true,
        containerId: true,
        createdAt: true,
        updatedAt: true,
        startedAt: true,
        stoppedAt: true,
      },
    });

    return {
      success: true,
      deployment,
    };
  } catch (error: any) {
    console.error("Error updating deployment:", error);
    throw error;
  }
};

export const getProjectDeployments = async (payload: ProjectIdPayload) => {
  try {
    const { projectId } = payload;

    const deployments = await prisma.deployment.findMany({
      where: { projectId },
      select: {
        id: true,
        commitSha: true,
        status: true,
        projectId: true,
        containerId: true,
        createdAt: true,
        updatedAt: true,
        startedAt: true,
        stoppedAt: true,
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    if (!deployments || deployments.length === 0) {
      return {
        success: false,
        message: "No deployments found for this project",
      };
    }

    return {
      success: true,
      deployments,
    };
  } catch (error: any) {
    console.error("Error fetching project deployments:", error);
    throw error;
  }
};
