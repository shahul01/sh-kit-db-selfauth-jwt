import { json, redirect } from '@sveltejs/kit';
import { getDb } from '$lib/server/db';
import { hashPassword } from '$lib/server/auth';
import type { RequestHandler } from './$types';
import type { PageServerLoad } from '../../todos/$types';

export const GET: PageServerLoad = async ({ locals }) => {
	if (locals.userId) {
		throw redirect(302, '/todos');
	}
};

export const POST: RequestHandler = async ({ request }) => {
	const { username, password } = await request.json();

	if (!username || !password) {
		return json({ error: 'Missing username or password' }, { status: 400 });
	}

	const db = getDb();
	const hashedPassword = await hashPassword(password);

	try {
		const result = db
			.prepare('INSERT INTO users (username, password) VALUES (?, ?)')
			.run(username, hashedPassword);
		return json({ success: true, userId: result.lastInsertRowid });
	} catch (error) {
		console.error(error);
		return json({ error: 'Username already exists' }, { status: 400 });
	}
};
