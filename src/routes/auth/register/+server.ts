import { json, redirect } from '@sveltejs/kit';
import { getDb } from '$lib/server/db';
import { hashPassword } from '$lib/server/auth';
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
		console.error('Register GET error:', error);
		throw redirect(302, '/');
	}
};

/**
 * Validates username format and strength
 */
function validateUsername(username: string): string | null {
	if (username.length < 3 || username.length > 30) {
		return 'Username must be between 3 and 30 characters';
	}
	if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
		return 'Username can only contain letters, numbers, underscores, and hyphens';
	}
	return null;
}

/**
 * Validates password strength
 */
function validatePassword(password: string): string | null {
	if (password.length < 8) {
		return 'Password must be at least 8 characters long';
	}
	if (password.length > 128) {
		return 'Password must be less than 128 characters';
	}
	if (!/(?=.*[a-z])/.test(password)) {
		return 'Password must contain at least one lowercase letter';
	}
	if (!/(?=.*[A-Z])/.test(password)) {
		return 'Password must contain at least one uppercase letter';
	}
	if (!/(?=.*\d)/.test(password)) {
		return 'Password must contain at least one number';
	}
	return null;
}

/**
 * Validates registration input
 */
function validateRegistrationInput(username: unknown, password: unknown): string | null {
	if (!username || typeof username !== 'string') {
		return 'Username is required and must be a string';
	}
	if (!password || typeof password !== 'string') {
		return 'Password is required and must be a string';
	}

	const usernameError = validateUsername(username.trim());
	if (usernameError) return usernameError;

	const passwordError = validatePassword(password);
	if (passwordError) return passwordError;

	return null;
}

/**
 * Handles user registration
 */
export const POST: RequestHandler = async ({ request }: RequestEvent) => {
	try {
		// Parse request body
		let body;
		try {
			body = await request.json();
		} catch (parseError) {
			console.error('Failed to parse request body:', parseError);
			return json({ error: 'Invalid request format' }, { status: 400 });
		}

		const { username, password } = body;

		// Validate input
		const validationError = validateRegistrationInput(username, password);
		if (validationError) {
			return json({ error: validationError }, { status: 400 });
		}

		// Sanitize username
		const sanitizedUsername = username.trim().toLowerCase();

		// Database operations
		let db;
		try {
			db = getDb();
		} catch (dbError) {
			console.error('Database connection error:', dbError);
			return json({ error: 'Database connection failed' }, { status: 500 });
		}

		// Check if username exists
		try {
			const existingUser = db.prepare('SELECT id FROM users WHERE username = ?').get(sanitizedUsername);
			if (existingUser) {
				return json({ error: 'Username already exists' }, { status: 400 });
			}
		} catch (queryError) {
			console.error('Database query error:', queryError);
			return json({ error: 'Registration failed' }, { status: 500 });
		}

		// Hash password
		let hashedPassword: string;
		try {
			hashedPassword = await hashPassword(password);
		} catch (hashError) {
			console.error('Password hashing error:', hashError);
			return json({ error: 'Registration failed' }, { status: 500 });
		}

		// Insert new user
		try {
			const stmt = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)');
			const result = stmt.run(sanitizedUsername, hashedPassword);

			return json({
				success: true,
				message: 'Registration successful',
				userId: result.lastInsertRowid
			});
		} catch (insertError) {
			console.error('User insertion error:', insertError);
			// Check if it's a constraint violation
			if (insertError instanceof Error && insertError.message.includes('UNIQUE constraint')) {
				return json({ error: 'Username already exists' }, { status: 400 });
			}
			return json({ error: 'Registration failed' }, { status: 500 });
		}

	} catch (error) {
		console.error('Unexpected registration error:', error);
		return json({ error: 'Internal server error' }, { status: 500 });
	}
};
