import type { PageServerLoad } from './$types';
import { redirect, error } from '@sveltejs/kit';

/**
 * Ensures user is authenticated before accessing todos page
 */
export const load: PageServerLoad = async ({ locals }) => {
	try {
		if (!locals.userId) {
			throw redirect(302, '/auth/login');
		}

		// Return user context
		return {
			userId: locals.userId
		};
	} catch (err) {
		// If it's a redirect, re-throw it
		if (err instanceof Response) {
			throw err;
		}

		console.error('Todos page load error:', err);
		throw error(500, 'Failed to load page');
	}
};
