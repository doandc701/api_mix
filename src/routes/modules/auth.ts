import express from "express";
import {
  allAccess,
  userBoard,
  adminBoard,
  moderatorBoard,
} from "../../controllers/Authorization/UserController";

import { verifyToken, isAdmin, isModerator } from "../../middlewares/authJwt";
import {
  SignUp,
  SignIn,
  getAccount,
} from "../../controllers/Authentication/AuthController";

import {
  getRoles,
  postRoles,
} from "../../controllers/Authentication/RolesController";

import { loginAccountLimiter } from "../../services/rateLimit.service";

const router = express.Router();

// router.post("/auth/signup", postUsers);
router.get("/account", getAccount);
router.post("/signup", SignUp);
router.post("/signin", loginAccountLimiter, SignIn);

// Authorization:
// GET /api/test/all
// GET /api/test/user
// GET /api/test/mod
// GET /api/test/admin
router.get("/api/test/all", allAccess);
router.get("/api/test/user", verifyToken, userBoard);
router.get("/api/test/mod", [verifyToken, isModerator], moderatorBoard);
router.get("/api/test/admin", [verifyToken, isAdmin], adminBoard);

// roles
// roles
router.get("/role", getRoles);
router.post("/role", postRoles);
export default router;
