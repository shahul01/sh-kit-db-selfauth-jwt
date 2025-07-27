import { json } from '@sveltejs/kit';
import { getDb } from '$lib/server/db';
import { updateTodoRequestSchema, todoIdSchema } from '$lib/server/validation';
import { logError, logDbOperation } from '$lib/server/logger';
import { getClientIP } from '$lib/server/security';
import type { RequestHandler, RequestEvent } from './$types';

/**
 * Updates a specific todo (title and/or completed status) with enhanced security
 */
export const PATCH: RequestHandler = async ({ params, request, locals }: RequestEvent) => {
	const clientIP = getClientIP(request, Object.fromEntries(request.headers.entries()));
	const startTime = Date.now();

	try {
		// Authentication check
		if (!locals.userId) {
			return json({ error: 'Unauthorized' }, { status: 401 });
		}

		// Validate todo ID parameter with Zod
		const todoIdValidation = todoIdSchema.safeParse(params.id);
		if (!todoIdValidation.success) {
			return json({ error: 'Invalid todo ID' }, { status: 400 });
		}
		const todoId = todoIdValidation.data;

		// Parse and validate request body, validation is down below
		let body;
		try {
			body = await request.json();
		} catch (parseError) {
			logError(parseError instanceof Error ? parseError : new Error('JSON parse failed'), {
				action: 'todo_patch_parse',
				userId: locals.userId,
				todoId,
				ip: clientIP
			});
			return json({ error: 'Invalid request format' }, { status: 400 });
		}

		// Validate update data with Zod schema
		const validationResult = updateTodoRequestSchema.safeParse(body);
		if (!validationResult.success) {
			const errors = validationResult.error.errors.map(err =>
				`${err.path.join('.')}: ${err.message}`
			).join(', ');

			return json({
				error: 'Invalid input',
				details: errors
			}, { status: 400 });
		}

		const { title, completed } = validationResult.data;

		// Database operations with comprehensive error handling
		let db;
		try {
			db = getDb();
		} catch (dbError) {
			logError(dbError instanceof Error ? dbError : new Error('DB connection failed'), {
				action: 'todo_patch_db_connection',
				userId: locals.userId,
				todoId,
				ip: clientIP
			});
			return json({ error: 'Service temporarily unavailable' }, { status: 503 });
		}

		try {
			// Check if todo exists and belongs to user
			const checkStmt = db.prepare('SELECT id FROM todos WHERE id = ? AND user_id = ?');
			const existingTodo = checkStmt.get(todoId, locals.userId);

			if (!existingTodo) {
				return json({ error: 'Todo not found' }, { status: 404 });
			}

			// Build dynamic UPDATE query based on provided fields
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

			if (updates.length === 0) {
				return json({ error: 'No valid fields to update' }, { status: 400 });
			}

			// Execute update with prepared statement
			values.push(todoId, locals.userId);
			const updateStmt = db.prepare(`
				UPDATE todos
				SET ${updates.join(', ')}, updated_at = CURRENT_TIMESTAMP
				WHERE id = ? AND user_id = ?
			`);
			// NOTE: main code
			const result = updateStmt.run(...values);

			if (result.changes === 0) {
				return json({ error: 'Todo not found or no changes made' }, { status: 404 });
			}

			const duration = Date.now() - startTime;
			logDbOperation('UPDATE_TODO', 'todos', locals.userId, duration);

			return json({ success: true, message: 'Todo updated successfully' });

		} catch (queryError) {
			const duration = Date.now() - startTime;
			logError(queryError instanceof Error ? queryError : new Error('Todo update failed'), {
				action: 'todo_patch_query',
				userId: locals.userId,
				todoId,
				ip: clientIP,
				duration
			});
			return json({ error: 'Failed to update todo' }, { status: 500 });
		}

	} catch (error) {
		const duration = Date.now() - startTime;
		logError(error instanceof Error ? error : new Error('Unexpected todo PATCH error'), {
			action: 'todo_patch_unexpected',
			userId: locals.userId,
			todoId: params.id,
			ip: clientIP,
			duration
		});
		return json({ error: 'Internal server error' }, { status: 500 });
	}
};

/**
 * Deletes a specific todo with enhanced security
 */
export const DELETE: RequestHandler = async ({ params, locals, request }: RequestEvent) => {
	const clientIP = getClientIP(request, Object.fromEntries(request.headers.entries()));
	const startTime = Date.now();

	try {
		// Authentication check
		if (!locals.userId) {
			return json({ error: 'Unauthorized' }, { status: 401 });
		}

		// Validate todo ID parameter with Zod
		const todoIdValidation = todoIdSchema.safeParse(params.id);
		if (!todoIdValidation.success) {
			return json({ error: 'Invalid todo ID' }, { status: 400 });
		}
		const todoId = todoIdValidation.data;

		// Database operations with comprehensive error handling
		let db;
		try {
			db = getDb();
		} catch (dbError) {
			logError(dbError instanceof Error ? dbError : new Error('DB connection failed'), {
				action: 'todo_delete_db_connection',
				userId: locals.userId,
				todoId,
				ip: clientIP
			});
			return json({ error: 'Service temporarily unavailable' }, { status: 503 });
		}

		try {
			// Delete todo with ownership check
			const stmt = db.prepare('DELETE FROM todos WHERE id = ? AND user_id = ?');
			// NOTE: main code
			const result = stmt.run(todoId, locals.userId);

			if (result.changes === 0) {
				return json({ error: 'Todo not found' }, { status: 404 });
			}

			const duration = Date.now() - startTime;
			logDbOperation('DELETE_TODO', 'todos', locals.userId, duration);

			return json({ success: true, message: 'Todo deleted successfully' });

		} catch (queryError) {
			const duration = Date.now() - startTime;
			logError(queryError instanceof Error ? queryError : new Error('Todo deletion failed'), {
				action: 'todo_delete_query',
				userId: locals.userId,
				todoId,
				ip: clientIP,
				duration
			});
			return json({ error: 'Failed to delete todo' }, { status: 500 });
		}

	} catch (error) {
		const duration = Date.now() - startTime;
		logError(error instanceof Error ? error : new Error('Unexpected todo DELETE error'), {
			action: 'todo_delete_unexpected',
			userId: locals.userId,
			todoId: params.id,
			ip: clientIP,
			duration
		});
		return json({ error: 'Internal server error' }, { status: 500 });
	}
};