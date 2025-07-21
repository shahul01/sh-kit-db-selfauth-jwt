import { json, redirect } from '@sveltejs/kit';
import { getDb } from '$lib/server/db';
import { verifyPassword, createJWT } from '$lib/server/auth';
import type { RequestHandler } from './$types';
import type { PageServerLoad } from '../../todos/$types';

export const GET: PageServerLoad = async ({ locals }) => {
	if (locals.userId) {
		throw redirect(302, '/todos');
	}
};

export const POST: RequestHandler = async ({ request, cookies }) => {
	// TODO: add trycatch?
	const { username, password } = await request.json();

	if (!username || !password) {
		return json({ error: 'Missing username or password' }, { status: 400 });
	}

	const db = getDb();
	type User = {
		id: number;
		password: string;
	};
	const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username) as User;

	if (!user.id || !user.password) {
		return json({ error: 'Missing user id or password' }, { status: 400 });
	}

	const isPasswordVerified = await verifyPassword(user.password, password);
	if (!user || !isPasswordVerified) {
		return json({ error: 'Invalid credentials' }, { status: 401 });
	}

	const token = createJWT(user.id);
	cookies.set('jwt', token, {
		path: '/',
		httpOnly: true,
		sameSite: 'strict',
		secure: process.env.NODE_ENV === 'production',
		maxAge: 60 * 60 * 24 // 24 hours
	});

	return json({ success: true });
};
