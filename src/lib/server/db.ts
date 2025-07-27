import Database from 'better-sqlite3';
import type { Database as DatabaseType } from 'better-sqlite3';
import { env } from './env';
import { logger, logDbOperation } from './logger';
import { userRowSchema, todoRowSchema, type UserRow, type TodoRow } from './validation';

/**
 * Enhanced database module with security features
 */

let db: DatabaseType;

/**
 * Database configuration for security
 */
const DB_CONFIG = {
	readonly: false,
	fileMustExist: false,
	timeout: 5000,
	verbose: env.NODE_ENV === 'development' ? console.log : undefined,
};

/**
 * Connection pool for better performance
 */
interface ConnectionStats {
	totalQueries: number;
	successfulQueries: number;
	failedQueries: number;
	averageQueryTime: number;
	lastQuery: number;
}

const connectionStats: ConnectionStats = {
	totalQueries: 0,
	successfulQueries: 0,
	failedQueries: 0,
	averageQueryTime: 0,
	lastQuery: 0,
};

/**
 * Get database instance with connection management
 */
export function getDb(): DatabaseType {
	if (!db) {
		try {
			// Ensure the database directory exists
			const dbPath = env.DATABASE_PATH;
			logger.info('Connecting to database', { path: dbPath });

			// Create database connection
			db = new Database(dbPath, DB_CONFIG);

			// Test the connection with a simple query
			try {
				db.prepare('SELECT 1').get();
				logger.info('Database connection test successful');
			} catch (testError) {
				throw new Error(`Database connection test failed: ${testError instanceof Error ? testError.message : 'Unknown error'}`);
			}

			// Enable WAL mode for better concurrency
			db.pragma('journal_mode = WAL');

			// Enable foreign key constraints
			db.pragma('foreign_keys = ON');

			// Set timeout for busy database
			db.pragma('busy_timeout = 5000');

			// Secure temp store in memory
			db.pragma('temp_store = MEMORY');

			// Optimize for performance
			db.pragma('cache_size = -64000'); // 64MB cache
			db.pragma('mmap_size = 268435456'); // 256MB mmap

			logger.info('Database pragmas applied successfully');

			// Initialize database schema
			initDb();

			// Log successful connection
			logDbOperation('connect', undefined, undefined, undefined);
			logger.info('Database connected successfully', { path: dbPath });

		} catch (error) {
			const err = error instanceof Error ? error : new Error('Unknown database error');

			// Log detailed error information
			logger.error('Database connection failed', {
				error: err.message,
				stack: err.stack,
				path: env.DATABASE_PATH,
				config: DB_CONFIG
			});

			logDbOperation('connect', undefined, undefined, undefined, err);
			throw new Error(`Database connection failed: ${err.message}`);
		}
	}
	return db;
}

/**
 * Check if a column exists in a table
 */
function columnExists(tableName: string, columnName: string): boolean {
	try {
		const result = db.prepare(`PRAGMA table_info(${tableName})`).all() as Array<{
			cid: number;
			name: string;
			type: string;
			notnull: number;
			dflt_value: string | null;
			pk: number;
		}>;
		return result.some(col => col.name === columnName);
	} catch (error) {
		logger.error('Error checking column existence', { tableName, columnName, error });
		return false;
	}
}

/**
 * Run database migrations to update schema
 */
function runMigrations(): void {
	logger.info('Running database migrations...');

	try {
		// Migration 1: Add missing columns to users table
		if (!columnExists('users', 'last_login_at')) {
			db.exec('ALTER TABLE users ADD COLUMN last_login_at DATETIME');
			logger.info('Added last_login_at column to users table');
		}

		if (!columnExists('users', 'failed_login_attempts')) {
			db.exec('ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0');
			logger.info('Added failed_login_attempts column to users table');
		}

		if (!columnExists('users', 'account_locked_until')) {
			db.exec('ALTER TABLE users ADD COLUMN account_locked_until DATETIME');
			logger.info('Added account_locked_until column to users table');
		}

		if (!columnExists('users', 'updated_at')) {
			// SQLite doesn't allow CURRENT_TIMESTAMP as default in ALTER TABLE
			// So we add the column without default, then update existing rows
			db.exec('ALTER TABLE users ADD COLUMN updated_at DATETIME');
			db.exec('UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL');
			logger.info('Added updated_at column to users table');
		}

		// Migration 2: Add missing columns to todos table if needed
		if (!columnExists('todos', 'updated_at')) {
			// Same issue - add without default, then update existing rows
			db.exec('ALTER TABLE todos ADD COLUMN updated_at DATETIME');
			db.exec('UPDATE todos SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL');
			logger.info('Added updated_at column to todos table');
		}

		logger.info('Database migrations completed successfully');

	} catch (error) {
		const err = error instanceof Error ? error : new Error('Migration failed');
		logger.error('Database migration failed', { error: err.message, stack: err.stack });
		throw err;
	}
}

/**
 * Initialize database schema with security considerations
 */
function initDb(): void {
	const startTime = Date.now();

	try {
		// First, ensure WAL mode is set and pragmas are applied
		db.pragma('journal_mode = WAL');
		db.pragma('foreign_keys = ON');
		db.pragma('busy_timeout = 5000');

		// Create tables with proper constraints and indexes
		const createTablesSQL = `
			-- Users table with security constraints
			CREATE TABLE IF NOT EXISTS users (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				username TEXT UNIQUE NOT NULL COLLATE NOCASE,
				password TEXT NOT NULL,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP
			);

			-- Todos table with proper relationships
			CREATE TABLE IF NOT EXISTS todos (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				user_id INTEGER NOT NULL,
				title TEXT NOT NULL,
				completed BOOLEAN DEFAULT FALSE,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

				-- Foreign key constraint
				FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,

				-- Constraints
				CHECK (length(title) >= 1 AND length(title) <= 500)
			);

			-- Security audit log table
			CREATE TABLE IF NOT EXISTS audit_log (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				user_id INTEGER,
				action TEXT NOT NULL,
				table_name TEXT,
				record_id INTEGER,
				old_values TEXT,
				new_values TEXT,
				ip_address TEXT,
				user_agent TEXT,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

				FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
			);

			-- Rate limiting table
			CREATE TABLE IF NOT EXISTS rate_limits (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				ip_address TEXT NOT NULL,
				endpoint TEXT NOT NULL,
				attempts INTEGER DEFAULT 1,
				window_start DATETIME DEFAULT CURRENT_TIMESTAMP,

				UNIQUE(ip_address, endpoint)
			);

			-- Session tracking table
			CREATE TABLE IF NOT EXISTS user_sessions (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				user_id INTEGER NOT NULL,
				token_id TEXT UNIQUE NOT NULL,
				fingerprint TEXT,
				ip_address TEXT,
				user_agent TEXT,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				expires_at DATETIME NOT NULL,
				revoked BOOLEAN DEFAULT FALSE,

				FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
			);
		`;

		db.exec(createTablesSQL);
		logger.info('Database tables created successfully');

		// Run migrations to add missing columns
		runMigrations();

		// Create indexes for performance and security
		const createIndexesSQL = `
			-- Performance indexes
			CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
			CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login_at);
			CREATE INDEX IF NOT EXISTS idx_todos_user_id ON todos(user_id);
			CREATE INDEX IF NOT EXISTS idx_todos_created_at ON todos(created_at);
			CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
			CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
			CREATE INDEX IF NOT EXISTS idx_rate_limits_ip_endpoint ON rate_limits(ip_address, endpoint);
			CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id);
			CREATE INDEX IF NOT EXISTS idx_sessions_token_id ON user_sessions(token_id);
			CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON user_sessions(expires_at);
		`;

		db.exec(createIndexesSQL);
		logger.info('Database indexes created successfully');

		// Create triggers for audit logging
		const createTriggersSQL = `
			-- Trigger for users table updates
			CREATE TRIGGER IF NOT EXISTS users_audit_update
			AFTER UPDATE ON users
			FOR EACH ROW
			BEGIN
				INSERT INTO audit_log (user_id, action, table_name, record_id, old_values, new_values)
				VALUES (
					NEW.id,
					'UPDATE',
					'users',
					NEW.id,
					json_object('username', OLD.username, 'updated_at', OLD.updated_at),
					json_object('username', NEW.username, 'updated_at', NEW.updated_at)
				);
			END;

			-- Trigger for todos table changes
			CREATE TRIGGER IF NOT EXISTS todos_audit_insert
			AFTER INSERT ON todos
			FOR EACH ROW
			BEGIN
				INSERT INTO audit_log (user_id, action, table_name, record_id, new_values)
				VALUES (
					NEW.user_id,
					'INSERT',
					'todos',
					NEW.id,
					json_object('title', NEW.title, 'completed', NEW.completed)
				);
			END;

			CREATE TRIGGER IF NOT EXISTS todos_audit_update
			AFTER UPDATE ON todos
			FOR EACH ROW
			BEGIN
				INSERT INTO audit_log (user_id, action, table_name, record_id, old_values, new_values)
				VALUES (
					NEW.user_id,
					'UPDATE',
					'todos',
					NEW.id,
					json_object('title', OLD.title, 'completed', OLD.completed),
					json_object('title', NEW.title, 'completed', NEW.completed)
				);
			END;

			CREATE TRIGGER IF NOT EXISTS todos_audit_delete
			BEFORE DELETE ON todos
			FOR EACH ROW
			BEGIN
				INSERT INTO audit_log (user_id, action, table_name, record_id, old_values)
				VALUES (
					OLD.user_id,
					'DELETE',
					'todos',
					OLD.id,
					json_object('title', OLD.title, 'completed', OLD.completed)
				);
			END;

			-- Update timestamps
			CREATE TRIGGER IF NOT EXISTS users_update_timestamp
			AFTER UPDATE ON users
			FOR EACH ROW
			BEGIN
				UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
			END;

			CREATE TRIGGER IF NOT EXISTS todos_update_timestamp
			AFTER UPDATE ON todos
			FOR EACH ROW
			BEGIN
				UPDATE todos SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
			END;
		`;

		db.exec(createTriggersSQL);
		logger.info('Database triggers created successfully');

		const duration = Date.now() - startTime;
		logDbOperation('init_schema', undefined, undefined, duration);
		logger.info('Database schema initialization completed successfully', { duration });

	} catch (error) {
		const err = error instanceof Error ? error : new Error('Schema initialization failed');
		const duration = Date.now() - startTime;

		// Log detailed error information
		logger.error('Database schema initialization failed', {
			error: err.message,
			stack: err.stack,
			duration,
			databasePath: env.DATABASE_PATH
		});

		logDbOperation('init_schema', undefined, undefined, duration, err);
		throw err;
	}
}

/**
 * Execute a query with performance monitoring and error handling
 */
function executeWithMonitoring<T>(
	operation: string,
	fn: () => T,
	userId?: number,
	tableName?: string
): T {
	const startTime = Date.now();
	connectionStats.totalQueries++;

	try {
		const result = fn();
		const duration = Date.now() - startTime;

		// Update stats
		connectionStats.successfulQueries++;
		connectionStats.lastQuery = Date.now();
		connectionStats.averageQueryTime =
			(connectionStats.averageQueryTime + duration) / 2;

		// Log successful operation
		logDbOperation(operation, tableName, userId, duration);

		return result;

	} catch (error) {
		const duration = Date.now() - startTime;
		const err = error instanceof Error ? error : new Error('Database operation failed');

		// Update stats
		connectionStats.failedQueries++;

		// Log failed operation
		logDbOperation(operation, tableName, userId, duration, err);

		throw err;
	}
}

/**
 * Secure database operations with validation
 */
export const dbOperations = {
	/**
	 * Create a new user with validation
	 */
	createUser(username: string, hashedPassword: string): number {
		return executeWithMonitoring(
			'create_user',
			() => {
				const stmt = db.prepare(`
					INSERT INTO users (username, password)
					VALUES (?, ?)
				`);
				const result = stmt.run(username, hashedPassword);
				return result.lastInsertRowid as number;
			},
			undefined,
			'users'
		);
	},

	/**
	 * Get user by username with validation
	 */
	getUserByUsername(username: string): UserRow | null {
		return executeWithMonitoring(
			'get_user_by_username',
			() => {
				// Check if account_locked_until column exists to avoid errors with old schema
				const hasLockColumn = columnExists('users', 'account_locked_until');

				let query = `
					SELECT id, username, password, created_at
					FROM users
					WHERE username = ?
				`;

				// Only add the lock check if the column exists
				if (hasLockColumn) {
					query += ` AND (account_locked_until IS NULL OR account_locked_until < CURRENT_TIMESTAMP)`;
				}

				const stmt = db.prepare(query);
				const result = stmt.get(username);
				return result ? userRowSchema.parse(result) : null;
			},
			undefined,
			'users'
		);
	},

	/**
	 * Update user login information
	 */
	updateUserLogin(userId: number, success: boolean): void {
		executeWithMonitoring(
			'update_user_login',
			() => {
				// Check which columns exist to avoid errors with old schema
				const hasLastLoginColumn = columnExists('users', 'last_login_at');
				const hasFailedAttemptsColumn = columnExists('users', 'failed_login_attempts');

				if (success) {
					const setParts: string[] = [];

					if (hasLastLoginColumn) {
						setParts.push('last_login_at = CURRENT_TIMESTAMP');
					}
					if (hasFailedAttemptsColumn) {
						setParts.push('failed_login_attempts = 0');
					}

					// Only update if we have columns to update
					if (setParts.length > 0) {
						const stmt = db.prepare(`
							UPDATE users
							SET ${setParts.join(', ')}
							WHERE id = ?
						`);
						stmt.run(userId);
					}
				} else {
					// Failed login - increment attempts if column exists
					if (hasFailedAttemptsColumn) {
						const stmt = db.prepare(`
							UPDATE users
							SET failed_login_attempts = failed_login_attempts + 1
							WHERE id = ?
						`);
						stmt.run(userId);
					}
				}
			},
			userId,
			'users'
		);
	},

	/**
	 * Get todos for user with validation
	 */
	getTodosByUserId(userId: number): TodoRow[] {
		return executeWithMonitoring(
			'get_todos_by_user',
			() => {
				const stmt = db.prepare(`
					SELECT id, user_id, title, completed, created_at
					FROM todos
					WHERE user_id = ?
					ORDER BY created_at DESC
				`);
				const results = stmt.all(userId);
				return results.map(row => todoRowSchema.parse(row));
			},
			userId,
			'todos'
		);
	},

	/**
	 * Create a new todo with validation
	 */
	createTodo(userId: number, title: string): number {
		return executeWithMonitoring(
			'create_todo',
			() => {
				const stmt = db.prepare(`
					INSERT INTO todos (user_id, title)
					VALUES (?, ?)
				`);
				const result = stmt.run(userId, title);
				return result.lastInsertRowid as number;
			},
			userId,
			'todos'
		);
	},

	/**
	 * Update todo with validation
	 */
	updateTodo(todoId: number, userId: number, updates: { title?: string; completed?: boolean }): boolean {
		return executeWithMonitoring(
			'update_todo',
			() => {
				const setParts: string[] = [];
				const values: (string | number)[] = [];

				if (updates.title !== undefined) {
					setParts.push('title = ?');
					values.push(updates.title);
				}

				if (updates.completed !== undefined) {
					setParts.push('completed = ?');
					values.push(updates.completed ? 1 : 0);
				}

				if (setParts.length === 0) {
					return false;
				}

				values.push(todoId, userId);

				const stmt = db.prepare(`
					UPDATE todos
					SET ${setParts.join(', ')}
					WHERE id = ? AND user_id = ?
				`);
				const result = stmt.run(...values);
				return result.changes > 0;
			},
			userId,
			'todos'
		);
	},

	/**
	 * Delete todo with validation
	 */
	deleteTodo(todoId: number, userId: number): boolean {
		return executeWithMonitoring(
			'delete_todo',
			() => {
				const stmt = db.prepare(`
					DELETE FROM todos
					WHERE id = ? AND user_id = ?
				`);
				const result = stmt.run(todoId, userId);
				return result.changes > 0;
			},
			userId,
			'todos'
		);
	},

	/**
	 * Log audit event
	 */
	logAuditEvent(
		userId: number | null,
		action: string,
		tableName?: string,
		recordId?: number,
		oldValues?: Record<string, unknown>,
		newValues?: Record<string, unknown>,
		ipAddress?: string,
		userAgent?: string
	): void {
		executeWithMonitoring(
			'log_audit_event',
			() => {
				const stmt = db.prepare(`
					INSERT INTO audit_log (
						user_id, action, table_name, record_id,
						old_values, new_values, ip_address, user_agent
					) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
				`);
				stmt.run(
					userId,
					action,
					tableName,
					recordId,
					oldValues ? JSON.stringify(oldValues) : null,
					newValues ? JSON.stringify(newValues) : null,
					ipAddress,
					userAgent
				);
			},
			userId || undefined,
			'audit_log'
		);
	},

	/**
	 * Session management
	 */
	createSession(
		userId: number,
		tokenId: string,
		fingerprint: string,
		ipAddress: string,
		userAgent: string,
		expiresAt: Date
	): void {
		executeWithMonitoring(
			'create_session',
			() => {
				const stmt = db.prepare(`
					INSERT INTO user_sessions (
						user_id, token_id, fingerprint, ip_address, user_agent, expires_at
					) VALUES (?, ?, ?, ?, ?, ?)
				`);
				stmt.run(userId, tokenId, fingerprint, ipAddress, userAgent, expiresAt.toISOString());
			},
			userId,
			'user_sessions'
		);
	},

	/**
	 * Revoke session
	 */
	revokeSession(tokenId: string): boolean {
		return executeWithMonitoring(
			'revoke_session',
			() => {
				const stmt = db.prepare(`
					UPDATE user_sessions
					SET revoked = TRUE
					WHERE token_id = ?
				`);
				const result = stmt.run(tokenId);
				return result.changes > 0;
			},
			undefined,
			'user_sessions'
		);
	},

	/**
	 * Clean expired sessions
	 */
	cleanExpiredSessions(): number {
		return executeWithMonitoring(
			'clean_expired_sessions',
			() => {
				const stmt = db.prepare(`
					DELETE FROM user_sessions
					WHERE expires_at < CURRENT_TIMESTAMP OR revoked = TRUE
				`);
				const result = stmt.run();
				return result.changes;
			},
			undefined,
			'user_sessions'
		);
	},
};

/**
 * Get database statistics
 */
export function getDbStats(): ConnectionStats & {
	uptime: number;
	dbSize?: number;
} {
	try {
		const uptime = Date.now() - connectionStats.lastQuery;
		let dbSize: number | undefined;

		try {
			const sizeResult = db.prepare('SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()').get() as { size: number } | undefined;
			dbSize = sizeResult?.size;
		} catch {
			// Ignore size calculation errors
		}

		return {
			...connectionStats,
			uptime,
			dbSize,
		};
	} catch (error) {
		logger.error('Failed to get database stats', { error });
		return {
			...connectionStats,
			uptime: 0,
		};
	}
}

/**
 * Database health check
 */
export function checkDbHealth(): { healthy: boolean; error?: string } {
	try {
		db.prepare('SELECT 1').get();
		return { healthy: true };
	} catch (error) {
		const err = error instanceof Error ? error : new Error('Unknown database error');
		logger.error('Database health check failed', { error: err.message });
		return { healthy: false, error: err.message };
	}
}

/**
 * Graceful database shutdown
 */
export function closeDb(): void {
	if (db) {
		try {
			// Clean up expired sessions before closing
			dbOperations.cleanExpiredSessions();

			// Close database connection
			db.close();

			logger.info('Database connection closed gracefully');
		} catch (error) {
			logger.error('Error closing database', { error });
		}
	}
}

// Periodic cleanup of expired sessions and audit logs
setInterval(() => {
	try {
		const cleanedSessions = dbOperations.cleanExpiredSessions();
		if (cleanedSessions > 0) {
			logger.info(`Cleaned ${cleanedSessions} expired sessions`);
		}

		// Clean old audit logs (keep last 30 days)
		const stmt = db.prepare(`
			DELETE FROM audit_log
			WHERE created_at < datetime('now', '-30 days')
		`);
		const cleanedLogs = stmt.run().changes;
		if (cleanedLogs > 0) {
			logger.info(`Cleaned ${cleanedLogs} old audit log entries`);
		}
	} catch (error) {
		logger.error('Periodic cleanup failed', { error });
	}
}, 24 * 60 * 60 * 1000); // Run daily