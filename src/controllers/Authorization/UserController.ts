import { Request, Response, NextFunction } from "express";

const allAccess = (req: Request, res: Response) => {
  res.status(200).send("Public Content.");
};
const userBoard = (req: Request, res: Response) => {
  res.status(200).send("User Content.");
};
const adminBoard = (req: Request, res: Response) => {
  res.status(200).send("Admin Content.");
};
const moderatorBoard = (req: Request, res: Response) => {
  res.status(200).send("Moderator Content.");
};
export { allAccess, userBoard, adminBoard, moderatorBoard };
