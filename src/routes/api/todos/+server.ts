import { json } from '@sveltejs/kit';
import { getDb } from '$lib/server/db';
import { createTodoRequestSchema, todoRowSchema } from '$lib/server/validation';
import { logError, logDbOperation } from '$lib/server/logger';
import { getClientIP } from '$lib/server/security';
import type { RequestHandler, RequestEvent } from './$types';

type RawTodo = {
	id: number;
	title: string;
	completed: boolean;
	created_at: string;
};

/**
 * Gets all todos for the authenticated user with enhanced security
 */
export const GET: RequestHandler = async ({ locals, request }: RequestEvent) => {
	const clientIP = getClientIP(request, Object.fromEntries(request.headers.entries()));
	const startTime = Date.now();

	try {
		// Authentication check
		if (!locals.userId) {
			return json({ error: 'Unauthorized' }, { status: 401 });
		}

		// Database operations with comprehensive error handling
		let db;
		try {
			db = getDb();
		} catch (dbError) {
			logError(dbError instanceof Error ? dbError : new Error('DB connection failed'), {
				action: 'todos_get_db_connection',
				userId: locals.userId,
				ip: clientIP
			});
			return json({ error: 'Service temporarily unavailable' }, { status: 503 });
		}

		// Query todos with enhanced error handling and validation
		try {
			const stmt = db.prepare(`
				SELECT id, title, completed, created_at
				FROM todos
				WHERE user_id = ?
				ORDER BY created_at DESC
			`);
			const rawTodos = stmt.all(locals.userId) as RawTodo[];

			// Validate each todo with Zod schema
			const validatedTodos = [];
			for (const rawTodo of rawTodos) {
				try {
					// Add user_id for validation
					const todoWithUserId = { ...rawTodo, user_id: locals.userId };
					const validationResult = todoRowSchema.safeParse(todoWithUserId);

					if (validationResult.success) {
						// Return only the fields needed by the client
						validatedTodos.push({
							id: validationResult.data.id,
							title: validationResult.data.title,
							completed: validationResult.data.completed,
							created_at: validationResult.data.created_at
						});
					} else {
						logError(new Error('Invalid todo data from database'), {
							action: 'todos_get_validation',
							todoId: rawTodo?.id,
							userId: locals.userId,
							ip: clientIP
						});
					}
				} catch (validationError) {
					logError(
						validationError instanceof Error
							? validationError
							: new Error('Todo validation failed'),
						{
							action: 'todos_get_validation_error',
							todoId: rawTodo?.id,
							userId: locals.userId,
							ip: clientIP
						}
					);
				}
			}

			const duration = Date.now() - startTime;
			logDbOperation('SELECT_TODOS', 'todos', locals.userId, duration);

			// NOTE: main code
			return json(validatedTodos);
		} catch (queryError) {
			const duration = Date.now() - startTime;
			logError(queryError instanceof Error ? queryError : new Error('Todos query failed'), {
				action: 'todos_get_query',
				userId: locals.userId,
				ip: clientIP,
				duration
			});
			return json({ error: 'Failed to fetch todos' }, { status: 500 });
		}
	} catch (error) {
		const duration = Date.now() - startTime;
		logError(error instanceof Error ? error : new Error('Unexpected todos GET error'), {
			action: 'todos_get_unexpected',
			userId: locals.userId,
			ip: clientIP,
			duration
		});
		return json({ error: 'Internal server error' }, { status: 500 });
	}
};

/**
 * Creates a new todo for the authenticated user with enhanced security
 */
export const POST: RequestHandler = async ({ request, locals }: RequestEvent) => {
	const clientIP = getClientIP(request, Object.fromEntries(request.headers.entries()));
	const startTime = Date.now();

	try {
		// Authentication check
		if (!locals.userId) {
			return json({ error: 'Unauthorized' }, { status: 401 });
		}

		// Parse and validate request body, validation is down below
		let body;
		try {
			body = await request.json();
		} catch (parseError) {
			logError(parseError instanceof Error ? parseError : new Error('JSON parse failed'), {
				action: 'todos_post_parse',
				userId: locals.userId,
				ip: clientIP
			});
			return json({ error: 'Invalid request format' }, { status: 400 });
		}

		// Validate with Zod schema
		const validationResult = createTodoRequestSchema.safeParse(body);
		if (!validationResult.success) {
			const errors = validationResult.error.errors
				.map((err) => `${err.path.join('.')}: ${err.message}`)
				.join(', ');

			return json(
				{
					error: 'Invalid input',
					details: errors
				},
				{ status: 400 }
			);
		}

		const { title } = validationResult.data;

		// Database operations with comprehensive error handling
		let db;
		try {
			db = getDb();
		} catch (dbError) {
			logError(dbError instanceof Error ? dbError : new Error('DB connection failed'), {
				action: 'todos_post_db_connection',
				userId: locals.userId,
				ip: clientIP
			});
			return json({ error: 'Service temporarily unavailable' }, { status: 503 });
		}

		// Insert new todo with enhanced error handling
		try {
			const stmt = db.prepare(`
				INSERT INTO todos (user_id, title, completed, created_at)
				VALUES (?, ?, FALSE, CURRENT_TIMESTAMP)
			`);
			// NOTE: main code
			const result = stmt.run(locals.userId, title);

			if (!result.lastInsertRowid) {
				throw new Error('Failed to get new todo ID');
			}

			const duration = Date.now() - startTime;
			logDbOperation('INSERT_TODO', 'todos', locals.userId, duration);

			return json({
				success: true,
				id: result.lastInsertRowid,
				message: 'Todo created successfully'
			});
		} catch (insertError) {
			const duration = Date.now() - startTime;
			logError(insertError instanceof Error ? insertError : new Error('Todo insertion failed'), {
				action: 'todos_post_insert',
				userId: locals.userId,
				title,
				ip: clientIP,
				duration
			});
			return json({ error: 'Failed to create todo' }, { status: 500 });
		}
	} catch (error) {
		const duration = Date.now() - startTime;
		logError(error instanceof Error ? error : new Error('Unexpected todos POST error'), {
			action: 'todos_post_unexpected',
			userId: locals.userId,
			ip: clientIP,
			duration
		});
		return json({ error: 'Internal server error' }, { status: 500 });
	}
};
