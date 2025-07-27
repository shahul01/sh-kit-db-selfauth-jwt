import { json } from '@sveltejs/kit';
import { logAuthEvent, logError } from '$lib/server/logger';
import { getClientIP } from '$lib/server/security';
import type { RequestHandler, RequestEvent } from './$types';

/**
 * Handles user logout with comprehensive security logging
 */
export const POST: RequestHandler = async ({ cookies, request, locals }: RequestEvent) => {
	const clientIP = getClientIP(request, Object.fromEntries(request.headers.entries()));
	const userAgent = request.headers.get('user-agent') || '';
	const userId = locals.userId;

	try {
		// Check if user was actually logged in
		const wasLoggedIn = !!userId;

		// Clear the JWT cookie with all security attributes
		cookies.delete('jwt', {
			path: '/',
			httpOnly: true,
			sameSite: 'strict',
			secure: process.env.NODE_ENV === 'production'
		});

		// Log the logout event
		if (wasLoggedIn) {
			logAuthEvent('logout', userId, clientIP, userAgent, true);
		}

		return json({
			success: true,
			message: 'Logged out successfully'
		});

	} catch (error) {
		logError(error instanceof Error ? error : new Error('Logout failed'), {
			action: 'logout_error',
			userId,
			ip: clientIP
		});

		// Even if there's an error, still try to clear the cookie
		try {
			cookies.delete('jwt', {
				path: '/',
				httpOnly: true,
				sameSite: 'strict',
				secure: process.env.NODE_ENV === 'production'
			});
		} catch (cookieError) {
			logError(cookieError instanceof Error ? cookieError : new Error('Cookie clearing failed'), {
				action: 'logout_cookie_clear_error',
				userId,
				ip: clientIP
			});
		}

		return json({ error: 'Logout failed' }, { status: 500 });
	}
};