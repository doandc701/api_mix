import express from "express";
import { Request, Response, NextFunction } from "express";
import bodyParser from "body-parser";
import cors from "cors";
import { connectToDb, getDb, connectMongoose } from "./config/connectDB";
import { routes } from "./routes/index";
import { apiLimit } from "./services/rateLimit.service";
const app = express();
const port = 3000;
const corsOptions = {
  origin: "http://localhost:8081",
};
app.use(bodyParser.json());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(apiLimit);
// cors
app.use(cors(corsOptions));
app.use(function (req: Request, res: Response, next: NextFunction) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept"
  );
  next();
});
routes(app);
connectMongoose();
app.listen(port, () => {
  console.log(`app listening on port http://localhost:${port}`);
});
