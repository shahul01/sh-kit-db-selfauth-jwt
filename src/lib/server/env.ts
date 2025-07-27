import { z } from 'zod';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

/**
 * Environment variable validation schema
 */
const envSchema = z.object({
	NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
	JWT_SECRET: z.string().min(32, 'JWT secret must be at least 32 characters'),
	JWT_EXPIRES_IN: z.string().default('24h'),
	PASSWORD_PEPPER: z.string().min(16, 'Password pepper must be at least 16 characters'),
	DATABASE_PATH: z.string().default('todo.db'),
	LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
	RATE_LIMIT_WINDOW_MS: z.coerce.number().default(15 * 60 * 1_000), // 15 minutes
	RATE_LIMIT_MAX_REQUESTS: z.coerce.number().default(100), // 100 requests per window
	RATE_LIMIT_AUTH_MAX: z.coerce.number().default(5), // 5 auth attempts per window
	ARGON2_MEMORY_COST: z.coerce.number().default(64 * 1024), // 64 MB
	ARGON2_TIME_COST: z.coerce.number().default(3), // 3 iterations
	ARGON2_PARALLELISM: z.coerce.number().default(4), // 4 threads
	CSP_REPORT_URI: z.string().optional(),
	ALLOWED_ORIGINS: z.string().optional().transform(str =>
		str ? str.split(',').map(origin => origin.trim()) : []
	),
});

/**
 * Validate and parse environment variables
 */
function validateEnv() {
	try {
		return envSchema.parse(process.env);
	} catch (error) {
		console.error('❌ Invalid environment variables:');
		if (error instanceof z.ZodError) {
			error.errors.forEach((err) => {
				console.error(`  - ${err.path.join('.')}: ${err.message}`);
			});
		}
		process.exit(1);
	}
}

/**
 * Validated environment configuration
 */
export const env = validateEnv();

/**
 * Type-safe environment configuration
 */
export type Env = z.infer<typeof envSchema>;

/**
 * Check if running in production
 */
export const isProduction = env.NODE_ENV === 'production';

/**
 * Check if running in development
 */
export const isDevelopment = env.NODE_ENV === 'development';

/**
 * Check if running in test environment
 */
export const isTest = env.NODE_ENV === 'test';