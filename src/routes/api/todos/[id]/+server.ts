import { json } from '@sveltejs/kit';
import { getDb } from '$lib/server/db';
import type { RequestHandler, RequestEvent } from './$types';

/**
 * Validates todo ID parameter
 */
function validateTodoId(id: string): number | null {
	const numId = parseInt(id, 10);
	if (isNaN(numId) || numId <= 0) {
		return null;
	}
	return numId;
}

type TodoUpdate = {
	title?: string;
	completed?: boolean;
}

/**
 * Validates todo update input
 */
function validateTodoUpdate(data: TodoUpdate): { title?: string; completed?: boolean; error?: string } {
	const result: { title?: string; completed?: boolean; error?: string } = {};

	if (data.title !== undefined) {
		if (typeof data.title !== 'string') {
			result.error = 'Title must be a string';
			return result;
		}
		const trimmedTitle = data.title.trim();
		if (trimmedTitle.length === 0) {
			result.error = 'Title cannot be empty';
			return result;
		}
		if (trimmedTitle.length > 500) {
			result.error = 'Title must be less than 500 characters';
			return result;
		}
		result.title = trimmedTitle;
	}

	if (data.completed !== undefined) {
		if (typeof data.completed !== 'boolean') {
			result.error = 'Completed must be a boolean';
			return result;
		}
		result.completed = data.completed;
	}

	return result;
}

/**
 * Updates a specific todo (title and/or completed status)
 */
export const PATCH: RequestHandler = async ({ params, request, locals }: RequestEvent) => {
	try {
		if (!locals.userId) {
			return json({ error: 'Unauthorized' }, { status: 401 });
		}

		// Validate todo ID
		const todoId = validateTodoId(params.id!);
		if (!todoId) {
			return json({ error: 'Invalid todo ID' }, { status: 400 });
		}

		// Parse request body
		let body;
		try {
			body = await request.json();
		} catch (parseError) {
			console.error('Failed to parse request body:', parseError);
			return json({ error: 'Invalid request format' }, { status: 400 });
		}

		// Validate update data
		const { title, completed, error: validationError } = validateTodoUpdate(body);
		if (validationError) {
			return json({ error: validationError }, { status: 400 });
		}

		if (title === undefined && completed === undefined) {
			return json({ error: 'No valid fields to update' }, { status: 400 });
		}

		// Database operations
		let db;
		try {
			db = getDb();
		} catch (dbError) {
			console.error('Database connection error:', dbError);
			return json({ error: 'Database connection failed' }, { status: 500 });
		}

		try {
			// Check if todo exists and belongs to user
			const checkStmt = db.prepare('SELECT id FROM todos WHERE id = ? AND user_id = ?');
			const existingTodo = checkStmt.get(todoId, locals.userId);

			if (!existingTodo) {
				return json({ error: 'Todo not found' }, { status: 404 });
			}

			// Update todo fields
			const updates: string[] = [];
			const values: (string | number)[] = [];

			if (title !== undefined) {
				updates.push('title = ?');
				values.push(title);
			}

			if (completed !== undefined) {
				updates.push('completed = ?');
				values.push(completed ? 1 : 0);
			}

			if (updates.length > 0) {
				values.push(todoId, locals.userId);
				const updateStmt = db.prepare(`
					UPDATE todos
					SET ${updates.join(', ')}
					WHERE id = ? AND user_id = ?
				`);
				updateStmt.run(...values);
			}

			return json({ success: true, message: 'Todo updated successfully' });

		} catch (queryError) {
			console.error('Database query error:', queryError);
			return json({ error: 'Failed to update todo' }, { status: 500 });
		}

	} catch (error) {
		console.error('PATCH todo error:', error);
		return json({ error: 'Internal server error' }, { status: 500 });
	}
};

/**
 * Deletes a specific todo
 */
export const DELETE: RequestHandler = async ({ params, locals }: RequestEvent) => {
	try {
		if (!locals.userId) {
			return json({ error: 'Unauthorized' }, { status: 401 });
		}

		// Validate todo ID
		const todoId = validateTodoId(params.id!);
		if (!todoId) {
			return json({ error: 'Invalid todo ID' }, { status: 400 });
		}

		// Database operations
		let db;
		try {
			db = getDb();
		} catch (dbError) {
			console.error('Database connection error:', dbError);
			return json({ error: 'Database connection failed' }, { status: 500 });
		}

		try {
			const stmt = db.prepare('DELETE FROM todos WHERE id = ? AND user_id = ?');
			const result = stmt.run(todoId, locals.userId);

			if (result.changes === 0) {
				return json({ error: 'Todo not found' }, { status: 404 });
			}

			return json({ success: true, message: 'Todo deleted successfully' });

		} catch (queryError) {
			console.error('Database query error:', queryError);
			return json({ error: 'Failed to delete todo' }, { status: 500 });
		}

	} catch (error) {
		console.error('DELETE todo error:', error);
		return json({ error: 'Internal server error' }, { status: 500 });
	}
};