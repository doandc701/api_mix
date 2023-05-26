import mongoose from "mongoose";
import { ObjectUsers } from "./user.model";
import { ObjectRole } from "./role.model";
mongoose.Promise = global.Promise;

export const ObjectDatabase = {
  user: ObjectUsers,
  role: ObjectRole,
  mongoose,
};
