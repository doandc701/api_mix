import rateLimit from "express-rate-limit";
import { Request, Response } from "express";
import RedisStore from "rate-limit-redis";
import { client } from "./redis.service";

const apiLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: "Too many connection",
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: any, res: Response) => {
    res.status(429).send({
      status: 500,
      message: "Too many request",
    });
    // console.log(req.ip);
  },
  skip: (req: Request, res: Response) => {
    // if (req.ip === "::1") return true;
    return false;
  },
  store: new RedisStore({
    // @ts-expect-error - Known issue: the `call` function is not present in @types/ioredis
    sendCommand: (...args: string[]) => client.call(...args),
  }),
});

const loginAccountLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minus
  max: 60,
  message:
    "Too many accounts created from this IP, please try again after an hour",
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  store: new RedisStore({
    // @ts-expect-error - Known issue: the `call` function is not present in @types/ioredis
    sendCommand: (...args: string[]) => client.call(...args),
  }),
});

export { apiLimit, loginAccountLimiter };
