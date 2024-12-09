import type { Handle } from '@sveltejs/kit';
import { verifyJWT } from '$lib/server/auth';

export const handle: Handle = async ({ event, resolve }) => {
    const token = event.cookies.get('jwt');

    if (token) {
        const payload = verifyJWT(token);
        if (payload) {
            event.locals.userId = payload.userId;
        }
    }

    return await resolve(event);
}; 