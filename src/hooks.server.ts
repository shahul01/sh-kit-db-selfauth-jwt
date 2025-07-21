import type { Handle } from '@sveltejs/kit';
import { verifyJWT } from '$lib/server/auth';

/**
 * SvelteKit hooks handler for JWT authentication
 * Verifies JWT tokens and sets user context
 */
export const handle: Handle = async ({ event, resolve }) => {
    try {
        const token = event.cookies.get('jwt');

        if (token) {
            try {
                const payload = verifyJWT(token);
                if (payload?.userId) {
                    event.locals.userId = payload.userId;
                } else {
                    // Invalid token, clear the cookie
                    event.cookies.delete('jwt', {
                        path: '/',
                        httpOnly: true,
                        sameSite: 'strict',
                        secure: process.env.NODE_ENV === 'production'
                    });
                }
            } catch (jwtError) {
                console.error('JWT verification error:', jwtError);
                // Clear invalid cookie
                event.cookies.delete('jwt', {
                    path: '/',
                    httpOnly: true,
                    sameSite: 'strict',
                    secure: process.env.NODE_ENV === 'production'
                });
            }
        }

        return await resolve(event);
    } catch (error) {
        console.error('Hook handler error:', error);
        // Continue processing even if hook fails
        return await resolve(event);
    }
};