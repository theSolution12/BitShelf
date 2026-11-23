/*
  Warnings:

  - You are about to drop the column `purpose` on the `otp_codes` table. All the data in the column will be lost.

*/
-- DropIndex
DROP INDEX "otp_codes_userId_purpose_idx";

-- AlterTable
ALTER TABLE "otp_codes" DROP COLUMN "purpose";

-- DropEnum
DROP TYPE "OtpPurpose";

-- CreateIndex
CREATE INDEX "otp_codes_userId_idx" ON "otp_codes"("userId");
