import { json } from '@sveltejs/kit';
import { getDb } from '$lib/server/db';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async ({ locals }) => {
    if (!locals.userId) {
        return json({ error: 'Unauthorized' }, { status: 401 });
    }

    const db = getDb();
    // in postgreSQL,
    // const todos = await client.query(
    //     'SELECT * FROM todos WHERE user_id = $1 ORDER BY created_at DESC',
    //     [locals.userId]
    // );
    const todos = db.prepare('SELECT * FROM todos WHERE user_id = ? ORDER BY created_at DESC')
        .all(locals.userId);

    return json(todos);
};

export const POST: RequestHandler = async ({ request, locals }) => {
    if (!locals.userId) {
        return json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { title } = await request.json();
    if (!title) {
        return json({ error: 'Title is required' }, { status: 400 });
    }

    const db = getDb();
    const result = db.prepare('INSERT INTO todos (user_id, title) VALUES (?, ?)')
        .run(locals.userId, title);

    return json({ id: result.lastInsertRowid });
};