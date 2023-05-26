import { MongoClient } from "mongodb";
import mongoose from "mongoose";

let dbConnetion: any;
const uriCloud: string =
  "mongodb+srv://books:j7yjNzJntNrwXHxp@clbook.lvbipmz.mongodb.net/?retryWrites=true&w=majority";
const uriLocal: string = "mongodb://localhost:27017/test";
export const connectToDb = (callback: any) => {
  MongoClient.connect(uriCloud)
    .then((client) => {
      dbConnetion = client.db();
      return callback();
    })
    .catch((error) => {
      console.log(error);
      return callback(error);
    });
};
export const getDb = () => dbConnetion;

export const connectMongoose = async () => {
  try {
    await mongoose.connect("mongodb://localhost:27017/Authentication");
    console.log("Connect successfully!");
  } catch (err) {
    console.log("Connect failed!", err);
  }
};

export const cleanup = () => {
  mongoose.connection.close();
};
process.on("SIGINT", cleanup);
process.on("SIGTERM", cleanup);
process.on("SIGHUP", cleanup);
