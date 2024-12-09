import * as argon2 from 'argon2';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key'; // In production, use environment variable

export async function hashPassword(password: string): Promise<string> {
    return await argon2.hash(password);
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
    return await argon2.verify(hash, password);
}

export function createJWT(userId: number): string {
    return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '24h' });
}

export function verifyJWT(token: string): { userId: number } | null {
    try {
        return jwt.verify(token, JWT_SECRET) as { userId: number };
    } catch {
        return null;
    }
} 