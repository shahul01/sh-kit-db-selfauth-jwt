import { json } from '@sveltejs/kit';
import { env, isProduction } from './env';
import { logger, logSecurityEvent, logRateLimitEvent, logSuspiciousActivity } from './logger';
import { validateIP } from './validation';

/**
 * Comprehensive security middleware for SvelteKit
 */

/**
 * Rate limiting storage
 */
interface RateLimitEntry {
	count: number;
	resetTime: number;
	blocked: boolean;
}

const rateLimitStore = new Map<string, RateLimitEntry>();

/**
 * Security headers configuration
 */
export const SECURITY_HEADERS = {
	'X-Content-Type-Options': 'nosniff',
	'X-Frame-Options': 'DENY',
	'X-XSS-Protection': '1; mode=block',
	'Referrer-Policy': 'strict-origin-when-cross-origin',
	'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()',
	'Strict-Transport-Security': isProduction ? 'max-age=31536000; includeSubDomains; preload' : '',
	'Cache-Control': 'no-cache, no-store, must-revalidate, private',
	'Pragma': 'no-cache',
	'Expires': '0',
};

/**
 * Content Security Policy configuration
 */
export function getCSPHeader(nonce?: string): string {
	const csp = [
		"default-src 'self'",
		"script-src 'self' 'unsafe-inline'", // SvelteKit needs unsafe-inline for hydration
		"style-src 'self' 'unsafe-inline'", // Tailwind and component styles
		"img-src 'self' data: blob:",
		"font-src 'self'",
		"connect-src 'self'",
		"media-src 'self'",
		"object-src 'none'",
		"base-uri 'self'",
		"form-action 'self'",
		"frame-ancestors 'none'",
		"upgrade-insecure-requests",
		...(env.CSP_REPORT_URI ? [`report-uri ${env.CSP_REPORT_URI}`] : []),
	];

	if (nonce) {
		csp[1] = `script-src 'self' 'nonce-${nonce}'`;
	}

	return csp.join('; ');
}

/**
 * Rate limiting configuration per endpoint
 */
const RATE_LIMITS = {
	'/api/auth/login': { windowMs: 15 * 60 * 1000, maxRequests: 5 }, // 5 login attempts per 15 min
	'/api/auth/register': { windowMs: 60 * 60 * 1000, maxRequests: 3 }, // 3 registrations per hour
	'/api/auth/logout': { windowMs: 5 * 60 * 1000, maxRequests: 10 }, // 10 logouts per 5 min
	'/api/todos': { windowMs: 15 * 60 * 1000, maxRequests: 100 }, // 100 todo operations per 15 min
	'default': { windowMs: env.RATE_LIMIT_WINDOW_MS, maxRequests: env.RATE_LIMIT_MAX_REQUESTS },
};

/**
 * Get client IP address with proxy support
 */
export function getClientIP(request: Request, headers: Record<string, string | undefined>): string {
	// Check various headers for real IP (in order of preference)
	const ipHeaders = [
		'cf-connecting-ip', // Cloudflare
		'x-real-ip', // Nginx
		'x-forwarded-for', // Standard proxy header
		'x-client-ip',
		'x-forwarded',
		'x-cluster-client-ip',
		'forwarded-for',
		'forwarded',
	];

	for (const header of ipHeaders) {
		const value = headers[header];
		if (value) {
			// X-Forwarded-For can contain multiple IPs, take the first one
			const ip = value.split(',')[0].trim();
			if (validateIP(ip)) {
				return ip;
			}
		}
	}

	// Fallback to request IP or localhost
	const url = new URL(request.url);
	return url.hostname === 'localhost' ? '127.0.0.1' : '0.0.0.0';
}

/**
 * Rate limiting implementation
 */
export function checkRateLimit(
	ip: string,
	endpoint: string,
	customLimits?: { windowMs: number; maxRequests: number }
): { allowed: boolean; resetTime?: number; remaining?: number } {
	const now = Date.now();
	const limits = customLimits || RATE_LIMITS[endpoint as keyof typeof RATE_LIMITS] || RATE_LIMITS.default;
	const key = `${ip}:${endpoint}`;

	let entry = rateLimitStore.get(key);

	// Initialize or reset if window expired
	if (!entry || now >= entry.resetTime) {
		entry = {
			count: 1,
			resetTime: now + limits.windowMs,
			blocked: false,
		};
		rateLimitStore.set(key, entry);

		logRateLimitEvent(ip, endpoint, 1, false);
		return {
			allowed: true,
			resetTime: entry.resetTime,
			remaining: limits.maxRequests - 1
		};
	}

	// Increment counter
	entry.count++;

	// Check if limit exceeded
	if (entry.count > limits.maxRequests) {
		entry.blocked = true;
		logRateLimitEvent(ip, endpoint, entry.count, true);

		// Log suspicious activity for excessive requests
		if (entry.count > limits.maxRequests * 2) {
			logSuspiciousActivity('excessive_requests', {
				endpoint,
				count: entry.count,
				limit: limits.maxRequests,
			}, ip);
		}

		return {
			allowed: false,
			resetTime: entry.resetTime,
			remaining: 0
		};
	}

	logRateLimitEvent(ip, endpoint, entry.count, false);
	return {
		allowed: true,
		resetTime: entry.resetTime,
		remaining: limits.maxRequests - entry.count
	};
}

/**
 * Security headers middleware
 */
export function setSecurityHeaders(response: Response): void {
	Object.entries(SECURITY_HEADERS).forEach(([header, value]) => {
		if (value) {
			response.headers.set(header, value);
		}
	});

	// Set CSP header
	response.headers.set('Content-Security-Policy', getCSPHeader());
}

/**
 * Request security validation
 */
export function validateRequest(request: Request, headers: Record<string, string | undefined>): {
	isValid: boolean;
	reason?: string;
	shouldBlock?: boolean;
} {
	const url = new URL(request.url);
	const userAgent = headers['user-agent'] || '';
	const contentType = headers['content-type'] || '';

	// Check for suspicious user agents
	const suspiciousUserAgents = [
		/bot/i,
		/crawler/i,
		/spider/i,
		/scraper/i,
		/sqlmap/i,
		/nikto/i,
		/nmap/i,
	];

	if (suspiciousUserAgents.some(pattern => pattern.test(userAgent))) {
		logSuspiciousActivity('suspicious_user_agent', { userAgent }, getClientIP(request, headers));
		return { isValid: false, reason: 'Suspicious user agent', shouldBlock: true };
	}

	// Validate content type for POST/PUT/PATCH requests
	if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
		if (!contentType.includes('application/json') && !contentType.includes('multipart/form-data')) {
			return { isValid: false, reason: 'Invalid content type' };
		}
	}

	// Check for path traversal attempts
	if (url.pathname.includes('..') || url.pathname.includes('%2e%2e')) {
		logSuspiciousActivity('path_traversal_attempt', { path: url.pathname }, getClientIP(request, headers));
		return { isValid: false, reason: 'Path traversal attempt', shouldBlock: true };
	}

	// Check for SQL injection patterns in URL
	const sqlPatterns = [
		/union\s+select/i,
		/or\s+1\s*=\s*1/i,
		/drop\s+table/i,
		/insert\s+into/i,
		/'.*or.*'/i,
	];

	if (sqlPatterns.some(pattern => pattern.test(url.search))) {
		logSuspiciousActivity('sql_injection_attempt', {
			path: url.pathname,
			query: url.search
		}, getClientIP(request, headers));
		return { isValid: false, reason: 'SQL injection attempt', shouldBlock: true };
	}

	// Check for XSS patterns in URL
	const xssPatterns = [
		/<script/i,
		/javascript:/i,
		/on\w+\s*=/i,
		/<iframe/i,
	];

	if (xssPatterns.some(pattern => pattern.test(decodeURIComponent(url.search)))) {
		logSuspiciousActivity('xss_attempt', {
			path: url.pathname,
			query: url.search
		}, getClientIP(request, headers));
		return { isValid: false, reason: 'XSS attempt', shouldBlock: true };
	}

	return { isValid: true };
}

/**
 * IP-based blocking (simple implementation)
 */
const blockedIPs = new Set<string>();
const ipBlockExpiry = new Map<string, number>();

export function blockIP(ip: string, durationMs: number = 60 * 60 * 1000): void {
	blockedIPs.add(ip);
	ipBlockExpiry.set(ip, Date.now() + durationMs);

	logSecurityEvent('ip_blocked', { ip, duration: durationMs }, 'warn');
}

export function isIPBlocked(ip: string): boolean {
	if (!blockedIPs.has(ip)) {
		return false;
	}

	const expiry = ipBlockExpiry.get(ip);
	if (expiry && Date.now() > expiry) {
		// Block expired, remove it
		blockedIPs.delete(ip);
		ipBlockExpiry.delete(ip);
		return false;
	}

	return true;
}

/**
 * CSRF token generation and validation
 */
const csrfTokens = new Map<string, { token: string; expiry: number }>();

export function generateCSRFToken(sessionId: string): string {
	const token = crypto.randomUUID();
	const expiry = Date.now() + (60 * 60 * 1000); // 1 hour

	csrfTokens.set(sessionId, { token, expiry });

	// Cleanup expired tokens
	setTimeout(() => {
		const entry = csrfTokens.get(sessionId);
		if (entry && Date.now() > entry.expiry) {
			csrfTokens.delete(sessionId);
		}
	}, 60 * 60 * 1000);

	return token;
}

export function validateCSRFToken(sessionId: string, token: string): boolean {
	const entry = csrfTokens.get(sessionId);

	if (!entry) {
		return false;
	}

	if (Date.now() > entry.expiry) {
		csrfTokens.delete(sessionId);
		return false;
	}

	return entry.token === token;
}

/**
 * Honeypot field validation (anti-bot measure)
 */
export function validateHoneypot(honeypotValue: string): boolean {
	// Honeypot field should always be empty for human users
	return honeypotValue === '' || honeypotValue === undefined;
}

/**
 * Request timing analysis for bot detection
 */
const requestTimings = new Map<string, number[]>();

export function analyzeRequestTiming(ip: string): { isSuspicious: boolean; reason?: string } {
	const now = Date.now();
	const timings = requestTimings.get(ip) || [];

	// Keep only last 10 requests
	timings.push(now);
	if (timings.length > 10) {
		timings.shift();
	}

	requestTimings.set(ip, timings);

	if (timings.length >= 5) {
		// Check for requests that are too fast (likely bot)
		const intervals = [];
		for (let i = 1; i < timings.length; i++) {
			intervals.push(timings[i] - timings[i - 1]);
		}

		const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;

		// If average interval is less than 100ms, likely a bot
		if (avgInterval < 100) {
			return { isSuspicious: true, reason: 'Requests too fast' };
		}

		// Check for perfectly regular intervals (bot-like behavior)
		const variance = intervals.reduce((sum, interval) => {
			return sum + Math.pow(interval - avgInterval, 2);
		}, 0) / intervals.length;

		if (variance < 10) { // Very low variance
			return { isSuspicious: true, reason: 'Too regular request pattern' };
		}
	}

	return { isSuspicious: false };
}

/**
 * Cleanup expired entries periodically
 */
setInterval(() => {
	const now = Date.now();

	// Cleanup rate limit entries
	for (const [key, entry] of rateLimitStore.entries()) {
		if (now >= entry.resetTime) {
			rateLimitStore.delete(key);
		}
	}

	// Cleanup IP blocks
	for (const [ip, expiry] of ipBlockExpiry.entries()) {
		if (now > expiry) {
			blockedIPs.delete(ip);
			ipBlockExpiry.delete(ip);
		}
	}

	// Cleanup request timings (keep only last hour)
	for (const [ip, timings] of requestTimings.entries()) {
		const recentTimings = timings.filter(time => now - time < 60 * 60 * 1000);
		if (recentTimings.length === 0) {
			requestTimings.delete(ip);
		} else {
			requestTimings.set(ip, recentTimings);
		}
	}

	// Cleanup CSRF tokens
	for (const [sessionId, entry] of csrfTokens.entries()) {
		if (now > entry.expiry) {
			csrfTokens.delete(sessionId);
		}
	}
}, 5 * 60 * 1000); // Every 5 minutes