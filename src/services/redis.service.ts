import RedisClient from "ioredis";

export const client = new RedisClient({
  port: 10788, // Redis port
  host: "redis-10788.c292.ap-southeast-1-1.ec2.cloud.redislabs.com", // Redis host
  username: "default", // needs Redis >= 6
  password: "k2TrEzCtJNV3TnV6WNt9vdQB1eDy9dCl",
  db: 0, // Defaults to 0
});
