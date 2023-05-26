import { Request, Response } from "express";
import authRouter from "./modules/auth";
export const routes = (app: any) => {
  // routes
  app.get("/", (req: Request, res: Response) => {
    res.json("Wellcome to api");
  });
  app.use("/auth", authRouter);
};
