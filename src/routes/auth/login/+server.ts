import { json, redirect } from '@sveltejs/kit';
import { getDb } from '$lib/server/db';
import { verifyPassword, createJWT } from '$lib/server/auth';
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
		console.error('Login GET error:', error);
		throw redirect(302, '/');
	}
};

/**
 * Validates input for login request
 */
function validateLoginInput(username: unknown, password: unknown): string | null {
	if (!username || typeof username !== 'string') {
		return 'Username is required and must be a string';
	}
	if (!password || typeof password !== 'string') {
		return 'Password is required and must be a string';
	}
	if (username.trim().length < 3) {
		return 'Username must be at least 3 characters long';
	}
	if (password.length < 6) {
		return 'Password must be at least 6 characters long';
	}
	return null;
}

/**
 * Handles user login
 */
export const POST: RequestHandler = async ({ request, cookies }: RequestEvent) => {
	try {
		// Parse and validate request body
		let body;
		try {
			body = await request.json();
		} catch (parseError) {
			console.error('Failed to parse request body:', parseError);
			return json({ error: 'Invalid request format' }, { status: 400 });
		}

		const { username, password } = body;

		// Validate input
		const validationError = validateLoginInput(username, password);
		if (validationError) {
			return json({ error: validationError }, { status: 400 });
		}

		// Sanitize username
		const sanitizedUsername = username.trim().toLowerCase();

		// Database operations with error handling
		let db;
		try {
			db = getDb();
		} catch (dbError) {
			console.error('Database connection error:', dbError);
			return json({ error: 'Database connection failed' }, { status: 500 });
		}

		// Query user with prepared statement
		type User = {
			id: number;
			password: string;
			username: string;
		};

		let user: User | undefined;
		try {
			const stmt = db.prepare('SELECT id, password, username FROM users WHERE username = ?');
			user = stmt.get(sanitizedUsername) as User | undefined;
		} catch (queryError) {
			console.error('Database query error:', queryError);
			return json({ error: 'Login failed' }, { status: 500 });
		}

		// Check if user exists
		if (!user?.id || !user?.password) {
			// Use same error for both cases to prevent username enumeration
			return json({ error: 'Invalid credentials' }, { status: 401 });
		}

		// Verify password
		let isPasswordVerified: boolean;
		try {
			isPasswordVerified = await verifyPassword(user.password, password);
		} catch (verifyError) {
			console.error('Password verification error:', verifyError);
			return json({ error: 'Authentication failed' }, { status: 500 });
		}

		if (!isPasswordVerified) {
			return json({ error: 'Invalid credentials' }, { status: 401 });
		}

		// Create JWT token
		let token: string;
		try {
			token = createJWT(user.id);
		} catch (tokenError) {
			console.error('JWT creation error:', tokenError);
			return json({ error: 'Authentication failed' }, { status: 500 });
		}

		// Set secure cookie
		try {
			cookies.set('jwt', token, {
				path: '/',
				httpOnly: true,
				sameSite: 'strict',
				secure: process.env.NODE_ENV === 'production',
				maxAge: 60 * 60 * 24 // 24 hours
			});
		} catch (cookieError) {
			console.error('Cookie setting error:', cookieError);
			return json({ error: 'Authentication failed' }, { status: 500 });
		}

		return json({ success: true, message: 'Login successful' });

	} catch (error) {
		console.error('Unexpected login error:', error);
		return json({ error: 'Internal server error' }, { status: 500 });
	}
};
