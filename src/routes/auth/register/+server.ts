import { json, redirect } from '@sveltejs/kit';
import { getDb } from '$lib/server/db';
import { hashPassword, checkAuthRateLimit } from '$lib/server/auth';
import { registerRequestSchema } from '$lib/server/validation';
import { logAuthEvent, logError, logSecurityEvent } from '$lib/server/logger';
import { getClientIP } from '$lib/server/security';
import type { RequestHandler, RequestEvent } from './$types';
import type { PageServerLoad } from '../../todos/$types';

/**
 * Redirect authenticated users to todos page
 */
export const GET: PageServerLoad = async ({ locals }) => {
	try {
		if (locals.userId) {
			throw redirect(302, '/todos');
		}
	} catch (error) {
		if (error instanceof Response) {
			throw error;
		}
		logError(error instanceof Error ? error : new Error('Unknown error'), {
			action: 'register_get_redirect'
		});
		throw redirect(302, '/');
	}
};

/**
 * Handles user registration with enhanced security
 */
export const POST: RequestHandler = async ({ request }: RequestEvent) => {
	const startTime = Date.now();
	const clientIP = getClientIP(request, Object.fromEntries(request.headers.entries()));
	const userAgent = request.headers.get('user-agent') || '';

	try {
		// Check rate limiting for registration attempts
		const rateLimitCheck = checkAuthRateLimit(clientIP);
		if (!rateLimitCheck.allowed) {
			const resetTime = rateLimitCheck.resetTime || Date.now() + 60 * 60 * 1000;
			const retryAfter = Math.ceil((resetTime - Date.now()) / 1000);

			logSecurityEvent('register_rate_limit_exceeded', {
				ip: clientIP,
				resetTime: new Date(resetTime).toISOString()
			}, 'warn');

			return json({
				error: 'Too many registration attempts. Please try again later.',
				retryAfter
			}, {
				status: 429,
				headers: {
					'Retry-After': retryAfter.toString()
				}
			});
		}

		// Parse request body with error handling, validation is down below
		let body;
		try {
			body = await request.json();
		} catch (parseError) {
			logSecurityEvent('register_invalid_json', {
				ip: clientIP,
				error: parseError instanceof Error ? parseError.message : 'Unknown'
			}, 'warn');
			return json({ error: 'Invalid request format' }, { status: 400 });
		}

		// Validate with Zod schema
		const validationResult = registerRequestSchema.safeParse(body);
		if (!validationResult.success) {
			const errors = validationResult.error.errors.map(err =>
				`${err.path.join('.')}: ${err.message}`
			).join(', ');

			logAuthEvent('failed_register', undefined, clientIP, userAgent, false);

			return json({
				error: 'Invalid input',
				details: errors
			}, { status: 400 });
		}

		const { username, password } = validationResult.data;

		// Database operations with comprehensive error handling
		let db;
		try {
			db = getDb();
		} catch (dbError) {
			logError(dbError instanceof Error ? dbError : new Error('DB connection failed'), {
				action: 'register_db_connection',
				ip: clientIP
			});
			return json({ error: 'Service temporarily unavailable' }, { status: 503 });
		}

		// Check if username already exists
		try {
			const existingUserStmt = db.prepare('SELECT id FROM users WHERE username = ?');
			const existingUser = existingUserStmt.get(username);

			if (existingUser) {
				logAuthEvent('failed_register', undefined, clientIP, userAgent, false);
				return json({ error: 'Username already exists' }, { status: 400 });
			}
		} catch (queryError) {
			logError(queryError instanceof Error ? queryError : new Error('Username check failed'), {
				action: 'register_username_check',
				username,
				ip: clientIP
			});
			return json({ error: 'Registration failed' }, { status: 500 });
		}

		// Hash password with enhanced security
		let hashedPassword: string;
		try {
			hashedPassword = await hashPassword(password);
		} catch (hashError) {
			logError(hashError instanceof Error ? hashError : new Error('Password hashing failed'), {
				action: 'register_password_hash',
				username,
				ip: clientIP
			});
			return json({ error: 'Registration failed' }, { status: 500 });
		}

		// Insert new user with transaction-like error handling
		let newUserId: number;
		try {
			const insertStmt = db.prepare(`
				INSERT INTO users (username, password, created_at)
				VALUES (?, ?, CURRENT_TIMESTAMP)
			`);
			// NOTE: main code
			const result = insertStmt.run(username, hashedPassword);
			newUserId = result.lastInsertRowid as number;

			if (!newUserId) {
				throw new Error('Failed to get new user ID');
			}
		} catch (insertError) {
			// Check if it's a constraint violation (duplicate username)
			if (insertError instanceof Error && insertError.message.includes('UNIQUE constraint')) {
				logAuthEvent('failed_register', undefined, clientIP, userAgent, false);
				return json({ error: 'Username already exists' }, { status: 400 });
			}

			logError(insertError instanceof Error ? insertError : new Error('User insertion failed'), {
				action: 'register_user_insert',
				username,
				ip: clientIP
			});
			return json({ error: 'Registration failed' }, { status: 500 });
		}

		// Log successful registration
		logAuthEvent('register', newUserId, clientIP, userAgent, true);

		// const duration = Date.now() - startTime;

		return json({
			success: true,
			message: 'Registration successful. You can now log in.',
			user: {
				id: newUserId,
				username: username
			}
		});

	} catch (error) {
		const duration = Date.now() - startTime;
		logError(error instanceof Error ? error : new Error('Unexpected registration error'), {
			action: 'register_unexpected_error',
			ip: clientIP,
			duration
		});
		return json({ error: 'Internal server error' }, { status: 500 });
	}
};
