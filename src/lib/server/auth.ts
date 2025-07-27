import * as argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import { createHash, randomBytes, timingSafeEqual } from 'crypto';
import { env } from './env';
import { logger } from './logger';

/**
 * Enhanced authentication with salting, peppering, and security features
 */

/**
 * Argon2 configuration for secure password hashing
 */
const ARGON2_OPTIONS: argon2.Options = {
	type: argon2.argon2id, // Most secure variant
	memoryCost: env.ARGON2_MEMORY_COST, // 64 MB
	timeCost: env.ARGON2_TIME_COST, // 3 iterations
	parallelism: env.ARGON2_PARALLELISM, // 4 threads
	hashLength: 32, // 32 bytes
	salt: 32 // 32 bytes
};

/**
 * JWT configuration
 */
const JWT_OPTIONS: jwt.SignOptions = {
	/** @ts-expect-error Type 'string' is not assignable to type 'number | StringValue | undefined'.ts(2322) */
	expiresIn: env.JWT_EXPIRES_IN,
	issuer: 'sh-kit-db-selfauth-jwt',
	audience: 'sh-kit-users',
	algorithm: 'HS512' // More secure than HS256
};

/**
 * Creates a cryptographic pepper for additional password security
 * Pepper is a secret value added to passwords before hashing
 */
function createPepper(password: string, salt: string): string {
	const pepperBase = env.PASSWORD_PEPPER;
	const combined = `${password}:${salt}:${pepperBase}`;
	return createHash('sha256').update(combined).digest('hex');
}

/**
 * Generates a cryptographically secure random salt
 */
function generateSalt(): string {
	return randomBytes(32).toString('hex');
}

/**
 * Hashes a password with salt and pepper using Argon2id
 */
export async function hashPassword(password: string): Promise<string> {
	try {
		// Input validation
		if (!password || typeof password !== 'string') {
			throw new Error('Password must be a non-empty string');
		}

		if (password.length > 128) {
			throw new Error('Password too long');
		}

		// Generate salt
		const salt = generateSalt();

		// Create pepper
		const pepper = createPepper(password, salt);

		// Combine password with pepper
		const pepperedPassword = `${password}${pepper}`;

		// Hash with Argon2id
		const hash = await argon2.hash(pepperedPassword, {
			...ARGON2_OPTIONS,
			salt: Buffer.from(salt, 'hex')
		});

		// Store salt with hash (format: argon2hash:salt)
		const saltedHash = `${hash}:${salt}`;

		logger.debug('Password hashed successfully', {
			saltLength: salt.length,
			hashLength: hash.length
		});

		return saltedHash;
	} catch (error) {
		logger.error('Password hashing failed', {
			error: error instanceof Error ? error.message : 'Unknown error'
		});
		throw new Error('Password hashing failed');
	}
}

/**
 * Verifies a password against a salted hash with pepper
 */
export async function verifyPassword(saltedHash: string, password: string): Promise<boolean> {
	try {
		// Input validation
		if (
			!saltedHash ||
			!password ||
			typeof saltedHash !== 'string' ||
			typeof password !== 'string'
		) {
			return false;
		}

		if (password.length > 128) {
			return false;
		}

		// Extract hash and salt
		const parts = saltedHash.split(':');
		if (parts.length !== 2) {
			logger.warn('Invalid salted hash format');
			return false;
		}

		const [hash, salt] = parts;

		// Create pepper with the stored salt
		const pepper = createPepper(password, salt);

		// Combine password with pepper
		const pepperedPassword = `${password}${pepper}`;

		// Verify with Argon2
		const isValid = await argon2.verify(hash, pepperedPassword);

		logger.debug('Password verification completed', { isValid });

		return isValid;
	} catch (error) {
		logger.error('Password verification failed', {
			error: error instanceof Error ? error.message : 'Unknown error'
		});
		return false;
	}
}

/**
 * Creates a secure JWT token with additional claims
 */
export function createJWT(userId: number, additionalClaims?: Record<string, unknown>): string {
	try {
		if (!userId || typeof userId !== 'number' || userId <= 0) {
			throw new Error('Invalid user ID');
		}

		const payload = {
			userId,
			tokenId: randomBytes(16).toString('hex'), // Unique token ID for revocation
			createdAt: Date.now(),
			...additionalClaims
		};

		const token = jwt.sign(payload, env.JWT_SECRET, JWT_OPTIONS);

		logger.debug('JWT created successfully', {
			userId,
			tokenId: payload.tokenId
		});

		return token;
	} catch (error) {
		logger.error('JWT creation failed', {
			error: error instanceof Error ? error.message : 'Unknown error',
			userId
		});
		throw new Error('Token creation failed');
	}
}

/**
 * Verifies and decodes a JWT token
 */
export function verifyJWT(
	token: string
): { userId: number; tokenId: string; createdAt: number } | null {
	try {
		if (!token || typeof token !== 'string') {
			return null;
		}

		// Verify token
		const decoded = jwt.verify(token, env.JWT_SECRET, {
			issuer: JWT_OPTIONS.issuer,
			audience: JWT_OPTIONS.audience as unknown as string,
			algorithms: [JWT_OPTIONS.algorithm as jwt.Algorithm]
		}) as { userId: number; tokenId: string; createdAt: number };

		// Validate required fields
		if (!decoded.userId || !decoded.tokenId || !decoded.createdAt) {
			logger.warn('JWT missing required fields');
			return null;
		}

		// Additional security checks
		const tokenAge = Date.now() - decoded.createdAt;
		const maxAge = 24 * 60 * 60 * 1000; // 24 hours in milliseconds

		if (tokenAge > maxAge) {
			logger.warn('JWT token too old', { tokenAge, maxAge });
			return null;
		}

		logger.debug('JWT verified successfully', {
			userId: decoded.userId,
			tokenId: decoded.tokenId
		});

		return {
			userId: decoded.userId,
			tokenId: decoded.tokenId,
			createdAt: decoded.createdAt
		};
	} catch (error) {
		if (error instanceof jwt.JsonWebTokenError) {
			logger.warn('JWT verification failed', { error: error.message });
		} else {
			logger.error('JWT verification error', {
				error: error instanceof Error ? error.message : 'Unknown error'
			});
		}
		return null;
	}
}

/**
 * Timing-safe comparison for sensitive data
 */
export function timingSafeCompare(a: string, b: string): boolean {
	try {
		if (typeof a !== 'string' || typeof b !== 'string') {
			return false;
		}

		if (a.length !== b.length) {
			return false;
		}

		const bufferA = Buffer.from(a, 'utf8');
		const bufferB = Buffer.from(b, 'utf8');

		return timingSafeEqual(bufferA, bufferB);
	} catch {
		return false;
	}
}

/**
 * Generates a secure random token for CSRF protection or API keys
 */
export function generateSecureToken(length: number = 32): string {
	return randomBytes(length).toString('hex');
}

/**
 * Creates a secure session fingerprint based on user agent and IP
 */
export function createSessionFingerprint(userAgent: string, ip: string): string {
	const combined = `${userAgent}:${ip}:${env.JWT_SECRET}`;
	return createHash('sha256').update(combined).digest('hex');
}

/**
 * Validates session fingerprint for additional security
 */
export function validateSessionFingerprint(stored: string, userAgent: string, ip: string): boolean {
	const current = createSessionFingerprint(userAgent, ip);
	return timingSafeCompare(stored, current);
}

/**
 * Password strength checker
 */
export function checkPasswordStrength(password: string): {
	score: number; // 0-5
	feedback: string[];
	isStrong: boolean;
} {
	const feedback: string[] = [];
	const passwordRegEx = /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/;
	let score = 0;

	// Length check
	if (password.length >= 8) score++;
	if (password.length >= 12) score++;

	// Character variety
	if (/[a-z]/.test(password)) score++;
	if (/[A-Z]/.test(password)) score++;
	if (/\d/.test(password)) score++;
	if (passwordRegEx.test(password)) score++;

	// Feedback
	if (password.length < 8) feedback.push('Use at least 8 characters');
	if (password.length < 12) feedback.push('Longer passwords are more secure');
	if (!/[a-z]/.test(password)) feedback.push('Add lowercase letters');
	if (!/[A-Z]/.test(password)) feedback.push('Add uppercase letters');
	if (!/\d/.test(password)) feedback.push('Add numbers');
	if (!passwordRegEx.test(password)) {
		feedback.push('Add special characters');
	}

	// Common patterns check
	const commonPatterns = ['123456', 'password', 'qwerty', 'admin'];
	if (commonPatterns.some((pattern) => password.toLowerCase().includes(pattern))) {
		feedback.push('Avoid common patterns and words');
		score = Math.max(0, score - 2);
	}

	return {
		score: Math.min(5, score),
		feedback,
		isStrong: score >= 4 && feedback.length <= 1
	};
}

/**
 * Rate limiting for authentication attempts
 */
const authAttempts = new Map<string, { count: number; lastAttempt: number }>();

/**
 * Checks if an IP has exceeded auth attempt limits
 */
export function checkAuthRateLimit(ip: string): { allowed: boolean; resetTime?: number } {
	const now = Date.now();
	const windowMs = env.RATE_LIMIT_WINDOW_MS;
	const maxAttempts = env.RATE_LIMIT_AUTH_MAX;

	const attempts = authAttempts.get(ip);

	if (!attempts) {
		authAttempts.set(ip, { count: 1, lastAttempt: now });
		return { allowed: true };
	}

	// Reset if window expired
	if (now - attempts.lastAttempt > windowMs) {
		authAttempts.set(ip, { count: 1, lastAttempt: now });
		return { allowed: true };
	}

	// Increment attempts
	attempts.count++;
	attempts.lastAttempt = now;

	if (attempts.count > maxAttempts) {
		const resetTime = attempts.lastAttempt + windowMs;
		return { allowed: false, resetTime };
	}

	return { allowed: true };
}

/**
 * Clears auth attempts for an IP (on successful login)
 */
export function clearAuthAttempts(ip: string): void {
	authAttempts.delete(ip);
}

/**
 * Periodic cleanup of old auth attempts
 */
setInterval(() => {
	const now = Date.now();
	const windowMs = env.RATE_LIMIT_WINDOW_MS;

	for (const [ip, attempts] of authAttempts.entries()) {
		if (now - attempts.lastAttempt > windowMs) {
			authAttempts.delete(ip);
		}
	}
}, env.RATE_LIMIT_WINDOW_MS);
