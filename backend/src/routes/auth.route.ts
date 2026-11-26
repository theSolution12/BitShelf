import { Router } from "express";
import {
  registerController,
  loginController,
  otpRequestController,
  otpVerifyController,
  logoutController,
} from "../controllers/auth.controller.js";

const router: Router = Router();

router.post("/register", registerController);
router.post("/login", loginController);
router.post("/otp/request", otpRequestController);
router.post("/otp/verify", otpVerifyController);
router.post("/logout", logoutController);

export default router;
