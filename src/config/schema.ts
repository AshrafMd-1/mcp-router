import { z } from 'zod';

export const configSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  HOST: z.string().default('0.0.0.0'),
  PORT: z.coerce.number().int().positive().default(3000),
  ADMIN_TOKEN: z.string().min(12),
  ADMIN_SESSION_HOURS: z.coerce.number().int().positive().default(24),
  DATABASE_URL: z.string().min(1),
  AUTO_MIGRATE: z.coerce.boolean().default(true),
  ENCRYPTION_KEY: z.string().min(32)
});

export type AppConfig = z.infer<typeof configSchema>;
