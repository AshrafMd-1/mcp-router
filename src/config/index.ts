import { config as loadDotEnv } from 'dotenv';
import { configSchema, type AppConfig } from './schema.js';

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  loadDotEnv({ quiet: true });
  return configSchema.parse(env);
}
