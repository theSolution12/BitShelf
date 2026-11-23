/*
  Warnings:

  - The `status` column on the `deployments` table would be dropped and recreated. This will lead to data loss if there is data in the column.
  - You are about to drop the column `projectPath` on the `projects` table. All the data in the column will be lost.

*/
-- CreateEnum
CREATE TYPE "DeploymentStatus" AS ENUM ('QUEUED', 'CLONING', 'BUILDING', 'DEPLOYING', 'RUNNING', 'FAILED', 'STOPPED', 'REMOVED');

-- AlterTable
ALTER TABLE "deployments" DROP COLUMN "status",
ADD COLUMN     "status" "DeploymentStatus" NOT NULL DEFAULT 'QUEUED';

-- AlterTable
ALTER TABLE "projects" DROP COLUMN "projectPath",
ADD COLUMN     "dockerfilePath" TEXT NOT NULL DEFAULT '.';

-- DropEnum
DROP TYPE "Status";
