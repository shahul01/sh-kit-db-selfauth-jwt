import { z } from 'zod';
import validator from 'validator';

/**
 * Custom Zod validators for enhanced security
 */

/**
 * Validates username format and security
 */
export const usernameSchema = z
	.string()
	.min(3, 'Username must be at least 3 characters')
	.max(30, 'Username must be no more than 30 characters')
	.regex(/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores, and hyphens')
	.refine((username) => !validator.contains(username.toLowerCase(), 'admin'), {
		message: 'Username cannot contain reserved words'
	})
	.refine((username) => !validator.contains(username.toLowerCase(), 'test'), {
		message: 'Username cannot contain reserved words'
	})
	.transform((username) => username.trim().toLowerCase());

/**
 * Validates password strength and security
 */
export const passwordSchema = z
	.string()
	.min(8, 'Password must be at least 8 characters')
	.max(128, 'Password must be no more than 128 characters')
	.refine((password) => /(?=.*[a-z])/.test(password), {
		message: 'Password must contain at least one lowercase letter'
	})
	.refine((password) => /(?=.*[A-Z])/.test(password), {
		message: 'Password must contain at least one uppercase letter'
	})
	.refine((password) => /(?=.*\d)/.test(password), {
		message: 'Password must contain at least one number'
	})
	.refine((password) => /(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])/.test(password), {
		message: 'Password must contain at least one special character'
	})
	.refine((password) => !validator.contains(password.toLowerCase(), 'password'), {
		message: 'Password cannot contain the word "password"'
	})
	.refine((password) => !validator.contains(password.toLowerCase(), '123456'), {
		message: 'Password cannot contain common sequences'
	});

/**
 * Validates todo title
 */
export const todoTitleSchema = z
	.string()
	.min(1, 'Todo title cannot be empty')
	.max(500, 'Todo title must be no more than 500 characters')
	.refine((title) => title.trim().length > 0, {
		message: 'Todo title cannot be only whitespace'
	})
	.refine((title) => !validator.contains(title, '<script'), {
		message: 'Todo title contains invalid content'
	})
	.transform((title) => validator.escape(title.trim()));

/**
 * Validates todo ID parameter
 */
export const todoIdSchema = z
	.string()
	.refine((id) => validator.isInt(id, { min: 1 }), {
		message: 'Invalid todo ID'
	})
	.transform((id) => parseInt(id, 10));

/**
 * Authentication request schemas
 */
export const loginRequestSchema = z.object({
	username: usernameSchema,
	password: z.string().min(1, 'Password is required')
});

export const registerRequestSchema = z.object({
	username: usernameSchema,
	password: passwordSchema
});

/**
 * Todo request schemas
 */
export const createTodoRequestSchema = z.object({
	title: todoTitleSchema
});

export const updateTodoRequestSchema = z.object({
	title: todoTitleSchema.optional(),
	completed: z.boolean().optional()
}).refine((data) => data.title !== undefined || data.completed !== undefined, {
	message: 'At least one field (title or completed) must be provided'
});

/**
 * Generic API response schemas
 */
export const apiSuccessResponseSchema = z.object({
	success: z.literal(true),
	message: z.string().optional(),
	data: z.any().optional()
});

export const apiErrorResponseSchema = z.object({
	error: z.string(),
	code: z.string().optional(),
	details: z.any().optional()
});

/**
 * Rate limiting request tracking schema
 */
export const rateLimitRequestSchema = z.object({
	ip: z.string().ip(),
	userAgent: z.string().optional(),
	endpoint: z.string(),
	timestamp: z.number(),
	userId: z.number().optional()
});

/**
 * Database row schemas for type safety
 */
export const userRowSchema = z.object({
	id: z.number(),
	username: z.string(),
	password: z.string(),
	created_at: z.string()
});

export const todoRowSchema = z.object({
	id: z.number(),
	user_id: z.number(),
	title: z.string(),
	completed: z.number().transform((val) => Boolean(val)),
	created_at: z.string()
});

/**
 * Type exports for better TypeScript integration
 */
export type LoginRequest = z.infer<typeof loginRequestSchema>;
export type RegisterRequest = z.infer<typeof registerRequestSchema>;
export type CreateTodoRequest = z.infer<typeof createTodoRequestSchema>;
export type UpdateTodoRequest = z.infer<typeof updateTodoRequestSchema>;
export type ApiSuccessResponse = z.infer<typeof apiSuccessResponseSchema>;
export type ApiErrorResponse = z.infer<typeof apiErrorResponseSchema>;
export type UserRow = z.infer<typeof userRowSchema>;
export type TodoRow = z.infer<typeof todoRowSchema>;

/**
 * Validation utility functions
 */

/**
 * Validates and sanitizes email (for future use)
 */
export const emailSchema = z
	.string()
	.email('Invalid email format')
	.refine((email) => validator.isEmail(email), {
		message: 'Invalid email format'
	})
	.transform((email) => validator.normalizeEmail(email) || email);

/**
 * Validates IP address
 */
export function validateIP(ip: string): boolean {
	return validator.isIP(ip);
}

/**
 * Validates URL
 */
export function validateURL(url: string): boolean {
	return validator.isURL(url, {
		protocols: ['http', 'https'],
		require_protocol: true
	});
}

/**
 * Sanitizes HTML input
 */
export function sanitizeHtml(input: string): string {
	return validator.escape(input);
}

/**
 * Checks for SQL injection patterns
 */
export function containsSQLInjection(input: string): boolean {
	const sqlPatterns = [
		/(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)/i,
		/(--|\/\*|\*\/|;|'|"|`)/,
		/(\b(OR|AND)\s+\d+\s*=\s*\d+)/i
	];

	return sqlPatterns.some(pattern => pattern.test(input));
}

/**
 * Validates and cleans user input
 */
export function validateUserInput(input: string, maxLength: number = 1000): {
	isValid: boolean;
	sanitized: string;
	errors: string[];
} {
	const errors: string[] = [];
	let sanitized = input;

	// Check length
	if (input.length > maxLength) {
		errors.push(`Input too long (max ${maxLength} characters)`);
	}

	// Check for SQL injection
	if (containsSQLInjection(input)) {
		errors.push('Input contains potentially malicious content');
	}

	// Sanitize
	sanitized = validator.escape(input.trim());

	return {
		isValid: errors.length === 0,
		sanitized,
		errors
	};
}