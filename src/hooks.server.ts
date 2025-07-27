import type { Handle } from '@sveltejs/kit';
import { sequence } from '@sveltejs/kit/hooks';
import { verifyJWT } from '$lib/server/auth';
import {
	setSecurityHeaders,
	getClientIP,
	checkRateLimit,
	validateRequest,
	isIPBlocked,
	blockIP,
	analyzeRequestTiming
} from '$lib/server/security';
import { logger, logApiRequest, logSecurityEvent, logSuspiciousActivity } from '$lib/server/logger';
import { json } from '@sveltejs/kit';

/**
 * Performance monitoring middleware
 */
const performanceMiddleware: Handle = async ({ event, resolve }) => {
	const startTime = Date.now();
	const { request } = event;
	const url = new URL(request.url);

	// Add request ID for tracing
	const requestId = crypto.randomUUID();
	event.locals.requestId = requestId;

	try {
		const response = await resolve(event);
		const duration = Date.now() - startTime;

		// Log API request
		const clientIP = getClientIP(request, Object.fromEntries(request.headers.entries()));
		logApiRequest(
			request.method,
			url.pathname,
			response.status,
			duration,
			event.locals.userId,
			clientIP,
			request.headers.get('user-agent') ?? undefined
		);

		return response;
	} catch (error) {
		const duration = Date.now() - startTime;
		logger.error(
			{
				requestId,
				method: request.method,
				path: url.pathname,
				duration,
				error: error instanceof Error ? error.message : 'Unknown error'
			},
			'Request failed'
		);
		throw error;
	}
};

/**
 * Security middleware for request validation and blocking
 */
const securityMiddleware: Handle = async ({ event, resolve }) => {
	const { request } = event;
	const headers = Object.fromEntries(request.headers.entries());
	const clientIP = getClientIP(request, headers);
	const url = new URL(request.url);

	// Check if IP is blocked
	if (isIPBlocked(clientIP)) {
		logSecurityEvent(
			'blocked_ip_request',
			{
				ip: clientIP,
				path: url.pathname,
				method: request.method
			},
			'warn'
		);

		return new Response('Access denied', {
			status: 403,
			headers: { 'Content-Type': 'text/plain' }
		});
	}

	// Validate request for security threats
	const validation = validateRequest(request, headers);
	if (!validation.isValid) {
		logSecurityEvent(
			'invalid_request',
			{
				ip: clientIP,
				path: url.pathname,
				reason: validation.reason,
				shouldBlock: validation.shouldBlock
			},
			'warn'
		);

		if (validation.shouldBlock) {
			// Temporarily block the IP
			blockIP(clientIP, 15 * 60 * 1000); // 15 minutes
		}

		return new Response('Bad request', {
			status: 400,
			headers: { 'Content-Type': 'text/plain' }
		});
	}

	// Analyze request timing for bot detection
	const timingAnalysis = analyzeRequestTiming(clientIP);
	if (timingAnalysis.isSuspicious) {
		logSuspiciousActivity(
			'bot_like_behavior',
			{
				reason: timingAnalysis.reason,
				path: url.pathname
			},
			clientIP
		);

		// Could implement additional bot protection here
	}

	return await resolve(event);
};

/**
 * Rate limiting middleware
 */
const rateLimitMiddleware: Handle = async ({ event, resolve }) => {
	const { request } = event;
	const url = new URL(request.url);
	const clientIP = getClientIP(request, Object.fromEntries(request.headers.entries()));

	// Skip rate limiting for static assets
	if (
		url.pathname.startsWith('/_app/') ??
		url.pathname.startsWith('/favicon') ??
		url.pathname.endsWith('.css') ??
		url.pathname.endsWith('.js') ??
		url.pathname.endsWith('.map')
	) {
		return await resolve(event);
	}

	// Check rate limit
	const rateLimitResult = checkRateLimit(clientIP, url.pathname);

	if (!rateLimitResult.allowed) {
		const resetTime = rateLimitResult.resetTime ?? Date.now() + 15 * 60 * 1000;
		const retryAfter = Math.ceil((resetTime - Date.now()) / 1000);

		logSecurityEvent(
			'rate_limit_exceeded',
			{
				ip: clientIP,
				path: url.pathname,
				resetTime: new Date(resetTime).toISOString()
			},
			'warn'
		);

		return new Response(
			JSON.stringify({
				error: 'Too many requests',
				retryAfter
			}),
			{
				status: 429,
				headers: {
					'Content-Type': 'application/json',
					'Retry-After': retryAfter.toString(),
					'X-RateLimit-Limit': '100',
					'X-RateLimit-Remaining': '0',
					'X-RateLimit-Reset': Math.floor(resetTime / 1000).toString()
				}
			}
		);
	}

	// Add rate limit headers to response
	const response = await resolve(event);

	if (rateLimitResult.remaining !== undefined) {
		response.headers.set('X-RateLimit-Remaining', rateLimitResult.remaining.toString());
	}
	if (rateLimitResult.resetTime) {
		response.headers.set(
			'X-RateLimit-Reset',
			Math.floor(rateLimitResult.resetTime / 1000).toString()
		);
	}

	return response;
};

/**
 * Authentication middleware with enhanced JWT handling
 */
const authMiddleware: Handle = async ({ event, resolve }) => {
	const token = event.cookies.get('jwt');
	const clientIP = getClientIP(event.request, Object.fromEntries(event.request.headers.entries()));

	if (token) {
		try {
			const payload = verifyJWT(token);
			if (payload?.userId) {
				event.locals.userId = payload.userId;
				event.locals.tokenId = payload.tokenId;
				event.locals.tokenCreatedAt = payload.createdAt;

				// Log successful token verification
				logger.debug('JWT verified successfully', {
					userId: payload.userId,
					tokenId: payload.tokenId,
					ip: clientIP,
					requestId: event.locals.requestId
				});
			} else {
				// Invalid token, clear the cookie
				event.cookies.delete('jwt', {
					path: '/',
					httpOnly: true,
					sameSite: 'strict',
					secure: process.env.NODE_ENV === 'production'
				});

				logSecurityEvent(
					'invalid_jwt_cleared',
					{
						ip: clientIP,
						reason: 'Invalid JWT payload'
					},
					'warn'
				);
			}
		} catch (jwtError) {
			logger.warn('JWT verification failed', {
				error: jwtError instanceof Error ? jwtError.message : 'Unknown error',
				ip: clientIP,
				requestId: event.locals.requestId
			});

			// Clear invalid cookie
			event.cookies.delete('jwt', {
				path: '/',
				httpOnly: true,
				sameSite: 'strict',
				secure: process.env.NODE_ENV === 'production'
			});

			logSecurityEvent(
				'jwt_verification_failed',
				{
					ip: clientIP,
					error: jwtError instanceof Error ? jwtError.message : 'Unknown error'
				},
				'warn'
			);
		}
	}

	return await resolve(event);
};

/**
 * Security headers middleware
 */
const headersMiddleware: Handle = async ({ event, resolve }) => {
	const response = await resolve(event);

	// Apply security headers
	setSecurityHeaders(response);

	// Add additional headers
	response.headers.set('X-Request-ID', event.locals.requestId ?? '');
	response.headers.set('X-Content-Type-Options', 'nosniff');

	return response;
};

/**
 * Error handling middleware
 */
const errorMiddleware: Handle = async ({ event, resolve }) => {
	try {
		return await resolve(event);
	} catch (error) {
		const clientIP = getClientIP(
			event.request,
			Object.fromEntries(event.request.headers.entries())
		);
		const url = new URL(event.request.url);

		logger.error('Unhandled request error', {
			error:
				error instanceof Error
					? {
							name: error.name,
							message: error.message,
							stack: error.stack
						}
					: error,
			method: event.request.method,
			path: url.pathname,
			ip: clientIP,
			userId: event.locals.userId,
			requestId: event.locals.requestId
		});

		// Return a secure error response
		if (event.request.headers.get('accept')?.includes('application/json')) {
			return json(
				{
					error: 'Internal server error',
					requestId: event.locals.requestId
				},
				{ status: 500 }
			);
		}

		return new Response('Internal server error', {
			status: 500,
			headers: { 'Content-Type': 'text/plain' }
		});
	}
};

/**
 * Compose all middleware in the correct order
 */
export const handle: Handle = sequence(
	errorMiddleware, // Error handling (outermost)
	performanceMiddleware, // Performance monitoring
	securityMiddleware, // Security validation
	rateLimitMiddleware, // Rate limiting
	authMiddleware, // Authentication
	headersMiddleware // Security headers (innermost)
);

/**
 * Handle server errors
 */
export const handleError = ({ error, event }) => {
	const clientIP = getClientIP(event.request, Object.fromEntries(event.request.headers.entries()));

	logger.error('Server error', {
		error:
			error instanceof Error
				? {
						name: error.name,
						message: error.message,
						stack: error.stack
					}
				: error,
		method: event.request.method,
		path: new URL(event.request.url).pathname,
		ip: clientIP,
		userId: event.locals.userId,
		requestId: event.locals.requestId
	});

	// Return a generic error message to avoid information leakage
	return {
		message: 'Internal server error',
		code: 'INTERNAL_ERROR',
		requestId: event.locals.requestId
	};
};
