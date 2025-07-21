import { json } from '@sveltejs/kit';
import type { RequestHandler, RequestEvent } from './$types';

/**
 * Handles user logout by clearing the JWT cookie
 */
export const POST: RequestHandler = async ({ cookies }: RequestEvent) => {
	try {
		// Clear the JWT cookie
		cookies.delete('jwt', {
			path: '/',
			httpOnly: true,
			sameSite: 'strict',
			secure: process.env.NODE_ENV === 'production'
		});

		return json({ success: true, message: 'Logged out successfully' });
	} catch (error) {
		console.error('Logout error:', error);
		return json({ error: 'Logout failed' }, { status: 500 });
	}
};