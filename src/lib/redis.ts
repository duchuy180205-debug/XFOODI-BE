import { createClient, RedisClientType } from 'redis';
import { ENV } from '../config/env';

const REDIS_URL = ENV.REDIS_URL || 'redis://localhost:6379';

const redisClient: RedisClientType<any, any, any> = createClient({
  url: REDIS_URL,
}) as RedisClientType<any, any, any>;

redisClient.on('error', (err) => console.log('Redis Client Error', err));
redisClient.on('connect', () => console.log('Redis Client Connected'));

redisClient.connect().catch(console.error);

export default redisClient;
