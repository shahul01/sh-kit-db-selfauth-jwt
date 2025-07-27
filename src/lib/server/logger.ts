import pino from 'pino';
import { env, isProduction, isDevelopment } from './env';

/**
 * Structured logging system with security considerations
 */

/**
 * Sensitive data patterns to redact from logs
 */
const SENSITIVE_PATTERNS = [
	/password/i,
	/secret/i,
	/token/i,
	/key/i,
	/auth/i,
	/session/i,
	/cookie/i,
	/bearer/i
];

/**
 * PII patterns to redact
 */
const PII_PATTERNS = [/email/i, /phone/i, /ssn/i, /credit/i, /card/i];

/**
 * Redacts sensitive information from log data
 */
function redactSensitiveData(obj: any): any {
	if (obj === null || obj === undefined) {
		return obj;
	}

	if (typeof obj === 'string') {
		// Don't log overly long strings that might contain sensitive data
		if (obj.length > 1000) {
			return '[REDACTED: Long string]';
		}

		// Check for JWT tokens
		if (obj.match(/^eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/)) {
			return '[REDACTED: JWT Token]';
		}

		// Check for potential secrets
		if (obj.length > 20 && /^[A-Za-z0-9+/=]+$/.test(obj)) {
			return '[REDACTED: Potential Secret]';
		}

		return obj;
	}

	if (typeof obj !== 'object' || Array.isArray(obj)) {
		return obj;
	}

	const redacted: any = {};

	for (const [key, value] of Object.entries(obj)) {
		const lowerKey = key.toLowerCase();

		// Check if key contains sensitive information
		const isSensitive = SENSITIVE_PATTERNS.some((pattern) => pattern.test(lowerKey));
		const isPII = PII_PATTERNS.some((pattern) => pattern.test(lowerKey));

		if (isSensitive || isPII) {
			redacted[key] = '[REDACTED]';
		} else {
			redacted[key] = redactSensitiveData(value);
		}
	}

	return redacted;
}

/**
 * Custom serializers for secure logging
 */
const serializers = {
	req: (req: any) => ({
		method: req.method,
		url: req.url,
		headers: redactSensitiveData(req.headers),
		remoteAddress: req.socket?.remoteAddress,
		userAgent: req.headers?.['user-agent']
	}),
	res: (res: any) => ({
		statusCode: res.statusCode,
		headers: redactSensitiveData(res.getHeaders?.())
	}),
	err: pino.stdSerializers.err,
	error: (err: Error) => ({
		name: err.name,
		message: err.message,
		stack: isDevelopment ? err.stack : undefined
	})
};

/**
 * Pino logger configuration
 */
const loggerConfig: pino.LoggerOptions = {
	level: env.LOG_LEVEL,
	serializers,
	redact: {
		paths: [
			'password',
			'token',
			'secret',
			'key',
			'authorization',
			'cookie',
			'*.password',
			'*.token',
			'*.secret',
			'*.key'
		],
		censor: '[REDACTED]'
	},
	...(isDevelopment && {
		transport: {
			target: 'pino-pretty',
			options: { colorize: true, ignore: 'pid,hostname', translateTime: 'yyyy-mm-dd HH:MM:ss' }
		}
	}),
	...(isProduction && {
		timestamp: pino.stdTimeFunctions.isoTime,
		formatters: { level: (label: string) => ({ level: label }) }
	})
};

/**
 * Create logger instance
 */
export const logger = pino(loggerConfig);

/**
 * Security event logger for audit trails
 */
export const securityLogger = logger.child({ component: 'security' });

/**
 * Database logger for DB operations
 */
export const dbLogger = logger.child({ component: 'database' });

/**
 * Auth logger for authentication events
 */
export const authLogger = logger.child({ component: 'auth' });

/**
 * API logger for request/response logging
 */
export const apiLogger = logger.child({ component: 'api' });

/**
 * Log security events with structured data
 */
export function logSecurityEvent(
	event: string,
	details: Record<string, any> = {},
	level: 'info' | 'warn' | 'error' = 'info'
) {
	const sanitizedDetails = redactSensitiveData(details);
	securityLogger[level](
		{ event, timestamp: new Date().toISOString(), ...sanitizedDetails },
		`Security event: ${event}`
	);
}

/**
 * Log authentication events
 */
export function logAuthEvent(
	action: 'login' | 'logout' | 'register' | 'password_change' | 'failed_register' | 'failed_login',
	userId?: number,
	ip?: string,
	userAgent?: string,
	success: boolean = true
) {
	authLogger.info(
		{ action, userId, ip, userAgent, success, timestamp: new Date().toISOString() },
		`Auth event: ${action}`
	);
}

/**
 * Log database operations
 */
export function logDbOperation(
	operation: string,
	table?: string,
	userId?: number,
	duration?: number,
	error?: Error
) {
	const logData = { operation, table, userId, duration, timestamp: new Date().toISOString() };

	if (error) {
		dbLogger.error({ ...logData, error: error.message }, `Database operation failed: ${operation}`);
	} else {
		dbLogger.info(logData, `Database operation: ${operation}`);
	}
}

/**
 * Log API requests with security context
 */
export function logApiRequest(
	method: string,
	path: string,
	statusCode: number,
	duration: number,
	userId?: number,
	ip?: string,
	userAgent?: string
) {
	apiLogger.info(
		{
			method,
			path,
			statusCode,
			duration,
			userId,
			ip,
			userAgent,
			timestamp: new Date().toISOString()
		},
		`${method} ${path} - ${statusCode} (${duration}ms)`
	);
}

/**
 * Log rate limiting events
 */
export function logRateLimitEvent(
	ip: string,
	endpoint: string,
	attempts: number,
	blocked: boolean = false
) {
	const level = blocked ? 'warn' : 'info';
	securityLogger[level](
		{ event: 'rate_limit', ip, endpoint, attempts, blocked, timestamp: new Date().toISOString() },
		`Rate limit ${blocked ? 'exceeded' : 'check'} for ${ip} on ${endpoint}`
	);
}

/**
 * Log suspicious activity
 */
export function logSuspiciousActivity(
	type: string,
	details: Record<string, any>,
	ip?: string,
	userId?: number
) {
	securityLogger.warn(
		{
			event: 'suspicious_activity',
			type,
			ip,
			userId,
			timestamp: new Date().toISOString(),
			...redactSensitiveData(details)
		},
		`Suspicious activity detected: ${type}`
	);
}

/**
 * Log application errors with context
 */
export function logError(error: Error, context: Record<string, any> = {}, userId?: number) {
	logger.error(
		{
			error: {
				name: error.name,
				message: error.message,
				stack: isDevelopment ? error.stack : undefined
			},
			context: redactSensitiveData(context),
			userId,
			timestamp: new Date().toISOString()
		},
		`Application error: ${error.message}`
	);
}

/**
 * Performance monitoring logger
 */
export function logPerformance(
	operation: string,
	duration: number,
	metadata: Record<string, any> = {}
) {
	const level = duration > 1000 ? 'warn' : 'info';
	logger[level](
		{
			operation,
			duration,
			metadata: redactSensitiveData(metadata),
			timestamp: new Date().toISOString()
		},
		`Performance: ${operation} took ${duration}ms`
	);
}

/**
 * Graceful shutdown for logger
 */
export function closeLogger(): Promise<void> {
	return new Promise((resolve) => {
		logger.flush();
		setTimeout(resolve, 100);
	});
}

// Log application startup
logger.info(
	{
		event: 'app_start',
		nodeEnv: env.NODE_ENV,
		logLevel: env.LOG_LEVEL,
		timestamp: new Date().toISOString()
	},
	'Application starting'
);

// Handle process events for logging
process.on('uncaughtException', (error) => {
	logger.fatal({ error }, 'Uncaught exception');
	process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
	logger.error({ reason, promise }, 'Unhandled promise rejection');
});

process.on('SIGTERM', async () => {
	logger.info('SIGTERM received, shutting down gracefully');
	await closeLogger();
	process.exit(0);
});

process.on('SIGINT', async () => {
	logger.info('SIGINT received, shutting down gracefully');
	await closeLogger();
	process.exit(0);
});
