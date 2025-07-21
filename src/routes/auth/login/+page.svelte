<script lang="ts">
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';

	let username = '';
	let password = '';
	let error = '';
	let loading = false;
	let mounted = false;

	onMount(() => {
		mounted = true;
	});

	/**
	 * Validates form input on client side
	 */
	function validateForm(): string | null {
		if (!username.trim()) {
			return 'Username is required';
		}
		if (username.trim().length < 3) {
			return 'Username must be at least 3 characters';
		}
		if (!password) {
			return 'Password is required';
		}
		if (password.length < 6) {
			return 'Password must be at least 6 characters';
		}
		return null;
	}

	/**
	 * Handles form submission with proper error handling
	 */
	async function handleSubmit() {
		if (!mounted) return;

		// Clear previous errors
		error = '';

		// Validate form
		const validationError = validateForm();
		if (validationError) {
			error = validationError;
			return;
		}

		loading = true;

		try {
			const response = await fetch('/auth/login', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					username: username.trim(),
					password
				})
			});

			let data;
			try {
				data = await response.json();
			} catch (parseError) {
				console.error('Failed to parse response:', parseError);
				error = 'Invalid server response';
				return;
			}

			if (response.ok) {
				// Successful login
				await goto('/todos');
			} else {
				// Handle different error status codes
				switch (response.status) {
					case 400:
						error = data.error || 'Invalid request';
						break;
					case 401:
						error = data.error || 'Invalid credentials';
						break;
					case 500:
						error = 'Server error. Please try again later.';
						break;
					default:
						error = data.error || 'Login failed';
				}
			}
		} catch (fetchError) {
			console.error('Network error:', fetchError);
			error = 'Network error. Please check your connection and try again.';
		} finally {
			loading = false;
		}
	}

	/**
	 * Handles Enter key press in form fields
	 */
	function handleKeydown(event: KeyboardEvent) {
		if (event.key === 'Enter' && !loading) {
			handleSubmit();
		}
	}
</script>

<svelte:window on:keydown={handleKeydown} />

<div class="mx-auto max-w-md p-6">
	<h1 class="mb-6 text-2xl font-bold">Login</h1>

	{#if error}
		<div class="mb-4 rounded bg-red-100 p-3 text-red-700" role="alert">
			{error}
		</div>
	{/if}

	<form on:submit|preventDefault={handleSubmit} class="space-y-4">
		<div>
			<label for="username" class="block text-sm font-medium">Username</label>
			<input
				id="username"
				type="text"
				bind:value={username}
				disabled={loading}
				class="mt-1 w-full rounded border p-2 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500 disabled:bg-gray-100"
				required
				autocomplete="username"
				aria-describedby="username-error"
			/>
		</div>

		<div>
			<label for="password" class="block text-sm font-medium">Password</label>
			<input
				id="password"
				type="password"
				bind:value={password}
				disabled={loading}
				class="mt-1 w-full rounded border p-2 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500 disabled:bg-gray-100"
				required
				autocomplete="current-password"
				aria-describedby="password-error"
			/>
		</div>

		<button
			type="submit"
			disabled={loading}
			class="w-full rounded bg-blue-500 p-2 text-white hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:bg-gray-400 disabled:cursor-not-allowed"
		>
			{loading ? 'Logging in...' : 'Login'}
		</button>
	</form>

	<p class="mt-4 text-center">
		Don't have an account?
		<a
			href="/auth/register"
			class="text-blue-500 hover:underline focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
		>
			Register
		</a>
	</p>
</div>
