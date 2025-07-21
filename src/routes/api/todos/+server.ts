import { json } from '@sveltejs/kit';
import { getDb } from '$lib/server/db';
import type { RequestHandler, RequestEvent } from './$types';

/**
 * Validates todo title input
 */
function validateTodoTitle(title: unknown): string | null {
	if (!title || typeof title !== 'string') {
		return 'Title is required and must be a string';
	}

	const trimmedTitle = title.trim();
	if (trimmedTitle.length === 0) {
		return 'Title cannot be empty';
	}
	if (trimmedTitle.length > 500) {
		return 'Title must be less than 500 characters';
	}

	return null;
}

/**
 * Gets all todos for the authenticated user
 */
export const GET: RequestHandler = async ({ locals }: RequestEvent) => {
	try {
		if (!locals.userId) {
			return json({ error: 'Unauthorized' }, { status: 401 });
		}

		let db;
		try {
			db = getDb();
		} catch (dbError) {
			console.error('Database connection error:', dbError);
			return json({ error: 'Database connection failed' }, { status: 500 });
		}

		try {
			const stmt = db.prepare(`
				SELECT id, title, completed, created_at
				FROM todos
				WHERE user_id = ?
				ORDER BY created_at DESC
			`);
			const todos = stmt.all(locals.userId);

			return json(todos);
		} catch (queryError) {
			console.error('Database query error:', queryError);
			return json({ error: 'Failed to fetch todos' }, { status: 500 });
		}

	} catch (error) {
		console.error('GET todos error:', error);
		return json({ error: 'Internal server error' }, { status: 500 });
	}
};

/**
 * Creates a new todo for the authenticated user
 */
export const POST: RequestHandler = async ({ request, locals }: RequestEvent) => {
	try {
		if (!locals.userId) {
			return json({ error: 'Unauthorized' }, { status: 401 });
		}

		// Parse request body
		let body;
		try {
			body = await request.json();
		} catch (parseError) {
			console.error('Failed to parse request body:', parseError);
			return json({ error: 'Invalid request format' }, { status: 400 });
		}

		const { title } = body;

		// Validate input
		const validationError = validateTodoTitle(title);
		if (validationError) {
			return json({ error: validationError }, { status: 400 });
		}

		const sanitizedTitle = title.trim();

		// Database operations
		let db;
		try {
			db = getDb();
		} catch (dbError) {
			console.error('Database connection error:', dbError);
			return json({ error: 'Database connection failed' }, { status: 500 });
		}

		try {
			const stmt = db.prepare(`
				INSERT INTO todos (user_id, title, completed, created_at)
				VALUES (?, ?, FALSE, CURRENT_TIMESTAMP)
			`);
			const result = stmt.run(locals.userId, sanitizedTitle);

			return json({
				success: true,
				id: result.lastInsertRowid,
				message: 'Todo created successfully'
			});
		} catch (insertError) {
			console.error('Todo insertion error:', insertError);
			return json({ error: 'Failed to create todo' }, { status: 500 });
		}

	} catch (error) {
		console.error('POST todos error:', error);
		return json({ error: 'Internal server error' }, { status: 500 });
	}
};