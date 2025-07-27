import { json, redirect } from '@sveltejs/kit';
import { getDb } from '$lib/server/db';
import { verifyPassword, createJWT, checkAuthRateLimit, clearAuthAttempts } from '$lib/server/auth';
import { loginRequestSchema, userRowSchema } from '$lib/server/validation';
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
		// If it's a redirect, re-throw it
		if (error instanceof Response) {
			throw error;
		}
		logError(error instanceof Error ? error : new Error('Unknown error'), {
			action: 'login_get_redirect'
		});
		throw redirect(302, '/');
	}
};

/**
 * Handles user login with enhanced security
 */
export const POST: RequestHandler = async ({ request, cookies }: RequestEvent) => {
	// const startTime = Date.now();
	const clientIP = getClientIP(request, Object.fromEntries(request.headers.entries()));
	const userAgent = request.headers.get('user-agent') || '';

	try {
		// Check rate limiting for this IP
		const rateLimitCheck = checkAuthRateLimit(clientIP);
		console.log(`clientIP: `, clientIP);
		if (!rateLimitCheck.allowed) {
			const resetTime = rateLimitCheck.resetTime || Date.now() + 15 * 60 * 1000;
			const retryAfter = Math.ceil((resetTime - Date.now()) / 1000);

			logSecurityEvent('login_rate_limit_exceeded', {
				ip: clientIP,
				resetTime: new Date(resetTime).toISOString()
			}, 'warn');

			return json({
				error: 'Too many login attempts. Please try again later.',
				retryAfter
			}, {
				status: 429,
				headers: {
					'Retry-After': retryAfter.toString()
				}
			});
		}

		// Parse and validate request body, validation is down below
		let body;
		try {
			body = await request.json();
		} catch (parseError) {
			logSecurityEvent('login_invalid_json', {
				ip: clientIP,
				error: parseError instanceof Error ? parseError.message : 'Unknown'
			}, 'warn');
			return json({ error: 'Invalid request format' }, { status: 400 });
		}

		// Validate with Zod schema
		const validationResult = loginRequestSchema.safeParse(body);
		if (!validationResult.success) {
			const errors = validationResult.error.errors.map(err =>
				`${err.path.join('.')}: ${err.message}`
			).join(', ');

			logAuthEvent('failed_login', undefined, clientIP, userAgent, false);

			return json({
				error: 'Invalid input',
				details: errors
			}, { status: 400 });
		}

		const { username, password } = validationResult.data;

		// Database operations with error handling
		let db;
		try {
			db = getDb();
		} catch (dbError) {
			logError(dbError instanceof Error ? dbError : new Error('DB connection failed'), {
				action: 'login_db_connection',
				ip: clientIP
			});
			return json({ error: 'Service temporarily unavailable' }, { status: 503 });
		}

		// Query user with prepared statement and validate with Zod
		let user;
		try {
			const stmt = db.prepare('SELECT id, password, username, created_at FROM users WHERE username = ?');
			const rawUser = stmt.get(username);

			if (!rawUser) {
				// User not found - same response as invalid password for security
				logAuthEvent('failed_login', undefined, clientIP, userAgent, false);
				return json({ error: 'Invalid credentials' }, { status: 401 });
			}

			// Validate user data with Zod
			const userValidation = userRowSchema.safeParse(rawUser);
			if (!userValidation.success) {
				logError(new Error('Invalid user data from database'), {
					action: 'login_user_validation',
					userId: (rawUser as Record<string, unknown>)?.id,
					ip: clientIP
				});
				return json({ error: 'Authentication failed' }, { status: 500 });
			}

			user = userValidation.data;
		} catch (queryError) {
			logError(queryError instanceof Error ? queryError : new Error('DB query failed'), {
				action: 'login_user_query',
				username,
				ip: clientIP
			});
			return json({ error: 'Authentication failed' }, { status: 500 });
		}

		// Verify password with timing-safe comparison
		let isPasswordVerified: boolean;
		try {
			isPasswordVerified = await verifyPassword(user.password, password);
		} catch (verifyError) {
			logError(verifyError instanceof Error ? verifyError : new Error('Password verification failed'), {
				action: 'login_password_verify',
				userId: user.id,
				ip: clientIP
			});
			return json({ error: 'Authentication failed' }, { status: 500 });
		}

		if (!isPasswordVerified) {
			logAuthEvent('failed_login', user.id, clientIP, userAgent, false);
			return json({ error: 'Invalid credentials' }, { status: 401 });
		}

		// Create JWT token with additional security claims
		let token: string;
		try {
			token = createJWT(user.id, {
				username: user.username,
				loginTime: Date.now(),
				ip: clientIP,
				userAgent: userAgent.substring(0, 100) // Limit length
			});
		} catch (tokenError) {
			logError(tokenError instanceof Error ? tokenError : new Error('JWT creation failed'), {
				action: 'login_jwt_creation',
				userId: user.id,
				ip: clientIP
			});
			return json({ error: 'Authentication failed' }, { status: 500 });
		}

		// Set secure cookie with additional security measures
		try {
			// NOTE: main code
			cookies.set('jwt', token, {
				path: '/',
				httpOnly: true,
				sameSite: 'strict',
				secure: process.env.NODE_ENV === 'production',
				maxAge: 60 * 60 * 24 // 24 hours
			});
		} catch (cookieError) {
			logError(cookieError instanceof Error ? cookieError : new Error('Cookie setting failed'), {
				action: 'login_cookie_set',
				userId: user.id,
				ip: clientIP
			});
			return json({ error: 'Authentication failed' }, { status: 500 });
		}

		// Clear auth attempts on successful login
		clearAuthAttempts(clientIP);

		// Log successful login
		logAuthEvent('login', user.id, clientIP, userAgent, true);

		return json({
			success: true,
			message: 'Login successful',
			user: {
				id: user.id,
				username: user.username
			}
		});

	} catch (error) {
		logError(error instanceof Error ? error : new Error('Unexpected login error'), {
			action: 'login_unexpected_error',
			ip: clientIP
		});
		return json({ error: 'Internal server error' }, { status: 500 });
	}
};
