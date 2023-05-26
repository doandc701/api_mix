import { client } from "../services/redis.service";

const setRedis = async ({ key, value }: any) => {
  try {
    const set = await client.set(key, value);
    return set;
  } catch (error) {
    console.log(error);
  }
};
const getRedis = async (key: string) => {
  try {
    const get = await client.get(key);
    return get;
  } catch (error) {
    console.log(error);
  }
};

export { getRedis, setRedis };
