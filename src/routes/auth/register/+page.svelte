<script lang="ts">
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';

	let username = '';
	let password = '';
	let confirmPassword = '';
	let error = '';
	let loading = false;
	let mounted = false;

	onMount(() => {
		mounted = true;
	});

	/**
	 * Validates username format
	 */
	function validateUsername(username: string): string | null {
		if (!username.trim()) {
			return 'Username is required';
		}
		if (username.trim().length < 3 || username.trim().length > 30) {
			return 'Username must be between 3 and 30 characters';
		}
		if (!/^[a-zA-Z0-9_-]+$/.test(username.trim())) {
			return 'Username can only contain letters, numbers, underscores, and hyphens';
		}
		return null;
	}

	/**
	 * Validates password strength
	 */
	function validatePassword(password: string): string | null {
		if (!password) {
			return 'Password is required';
		}
		if (password.length < 8) {
			return 'Password must be at least 8 characters long';
		}
		if (password.length > 128) {
			return 'Password must be less than 128 characters';
		}
		if (!/(?=.*[a-z])/.test(password)) {
			return 'Password must contain at least one lowercase letter';
		}
		if (!/(?=.*[A-Z])/.test(password)) {
			return 'Password must contain at least one uppercase letter';
		}
		if (!/(?=.*\d)/.test(password)) {
			return 'Password must contain at least one number';
		}
		return null;
	}

	/**
	 * Validates entire form
	 */
	function validateForm(): string | null {
		const usernameError = validateUsername(username);
		if (usernameError) return usernameError;

		const passwordError = validatePassword(password);
		if (passwordError) return passwordError;

		if (password !== confirmPassword) {
			return 'Passwords do not match';
		}

		return null;
	}

	/**
	 * Handles form submission with comprehensive error handling
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
			const response = await fetch('/auth/register', {
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
				// Successful registration
				await goto('/auth/login');
			} else {
				// Handle different error status codes
				switch (response.status) {
					case 400:
						error = data.error || 'Invalid registration data';
						break;
					case 500:
						error = 'Server error. Please try again later.';
						break;
					default:
						error = data.error || 'Registration failed';
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

	// Reactive password strength indicator
	$: passwordStrength = password ? validatePassword(password) : null;
	$: passwordsMatch = confirmPassword ? password === confirmPassword : true;
</script>

<svelte:window on:keydown={handleKeydown} />

<div class="mx-auto max-w-md p-6">
	<h1 class="mb-6 text-2xl font-bold">Register</h1>

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
			/>
			{#if username && validateUsername(username)}
				<p class="mt-1 text-sm text-red-600">{validateUsername(username)}</p>
			{/if}
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
				autocomplete="new-password"
			/>
			{#if password && passwordStrength}
				<p class="mt-1 text-sm text-red-600">{passwordStrength}</p>
			{/if}
		</div>

		<div>
			<label for="confirmPassword" class="block text-sm font-medium">Confirm Password</label>
			<input
				id="confirmPassword"
				type="password"
				bind:value={confirmPassword}
				disabled={loading}
				class="mt-1 w-full rounded border p-2 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500 disabled:bg-gray-100"
				required
				autocomplete="new-password"
			/>
			{#if confirmPassword && !passwordsMatch}
				<p class="mt-1 text-sm text-red-600">Passwords do not match</p>
			{/if}
		</div>

		<button
			type="submit"
			disabled={loading || !passwordsMatch || !!passwordStrength}
			class="w-full rounded bg-blue-500 p-2 text-white hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:bg-gray-400 disabled:cursor-not-allowed"
		>
			{loading ? 'Registering...' : 'Register'}
		</button>
	</form>

	<p class="mt-4 text-center">
		Already have an account?
		<a
			href="/auth/login"
			class="text-blue-500 hover:underline focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
		>
			Login
		</a>
	</p>
</div>
