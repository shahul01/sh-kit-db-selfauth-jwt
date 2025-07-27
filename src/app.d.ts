// See https://svelte.dev/docs/kit/types#app.d.ts
// for information about these interfaces
declare global {
	namespace App {
		interface Error {
			message: string;
			code?: string;
			requestId?: string;
		}
		interface Locals {
			userId: number | undefined;
			requestId?: string;
			tokenId?: string;
			tokenCreatedAt?: number;
		}
		// interface PageData {}
		// interface PageState {}
		// interface Platform {}
	}
}

export {};
