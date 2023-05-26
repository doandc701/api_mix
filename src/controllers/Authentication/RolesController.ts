import { Request, Response } from "express";
import { ObjectRole } from "../../models/auth/role.model";

export async function getRoles(req: Request, res: Response) {
  const page = req.query.p || 0;
  const showLimitRoles: number = 3;
  ObjectRole.find({})
    .sort({ name: 1 })
    .limit(showLimitRoles)
    .skip(Number(page) * showLimitRoles)
    .then((role) => {
      res.status(200).json(role);
    })
    .catch(() => {
      res.status(500).json({ error: "Could not fetch the documents" });
    });
}

export async function postRoles(req: Request, res: Response) {
  console.log(req.body.name);
  const test = new ObjectRole(req.body);
  await test
    .save()
    .then((add) => {
      res.json(add);
    })
    .catch((error) => {
      console.log(error);
      return;
    });
}
