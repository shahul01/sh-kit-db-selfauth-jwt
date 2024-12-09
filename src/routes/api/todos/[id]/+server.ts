import { json } from '@sveltejs/kit';
import { getDb } from '$lib/server/db';
import type { RequestHandler } from './$types';

export const PATCH: RequestHandler = async ({ params, request, locals }) => {
	if (!locals.userId) {
		return json({ error: 'Unauthorized' }, { status: 401 });
	}

	const { completed, title } = await request.json();
	const db = getDb();

	if (title !== undefined && typeof title === 'string') {
		db.prepare('UPDATE todos SET title = ? WHERE id = ? AND user_id = ?').run(
			title,
			params.id,
			locals.userId
		);
	}

	if (completed !== undefined && typeof completed === 'boolean') {
		db.prepare(
			'UPDATE todos SET completed = ? WHERE id = ? AND user_id = ?'
		).run(completed ? 1 : 0, params.id, locals.userId);
	}

	return json({ success: true });
};

export const DELETE: RequestHandler = async ({ params, locals }) => {
	if (!locals.userId) {
		return json({ error: 'Unauthorized' }, { status: 401 });
	}

	const db = getDb();
	db.prepare('DELETE FROM todos WHERE id = ? AND user_id = ?').run(params.id, locals.userId);

	return json({ success: true });
};