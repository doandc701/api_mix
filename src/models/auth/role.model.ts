import mongoose from "mongoose";

const { Schema } = mongoose;

const Role = new Schema(
  {
    name: String,
  },
  {
    timestamps: true,
  }
);
export const ObjectRole = mongoose.model("role", Role);
