import mongoose from "mongoose";

const { Schema } = mongoose;

const User = new Schema(
  {
    username: String,
    email: String,
    password: String,
    roles: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "role",
      },
    ],
  },
  {
    timestamps: true,
  }
);
export const ObjectUsers = mongoose.model("user", User);
