<script lang="ts">
	import { goto } from '$app/navigation';

	let username = '';
	let password = '';
	let confirmPassword = '';
	let error = '';

	async function handleSubmit() {
		if (password !== confirmPassword) {
			error = 'Passwords do not match';
			return;
		}

		const response = await fetch('/auth/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ username, password })
		});

		const data = await response.json();

		if (response.ok) {
			goto('/auth/login');
		} else {
			error = data.error || 'Registration failed';
		}
	}
</script>

<div class="mx-auto max-w-md p-6">
	<h1 class="mb-6 text-2xl font-bold">Register</h1>

	{#if error}
		<div class="mb-4 rounded bg-red-100 p-3 text-red-700">
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
				class="mt-1 w-full rounded border p-2"
				required
			/>
		</div>

		<div>
			<label for="password" class="block text-sm font-medium">Password</label>
			<input
				id="password"
				type="password"
				bind:value={password}
				class="mt-1 w-full rounded border p-2"
				required
			/>
		</div>

		<div>
			<label for="confirmPassword" class="block text-sm font-medium">Confirm Password</label>
			<input
				id="confirmPassword"
				type="password"
				bind:value={confirmPassword}
				class="mt-1 w-full rounded border p-2"
				required
			/>
		</div>

		<button type="submit" class="w-full rounded bg-blue-500 p-2 text-white hover:bg-blue-600">
			Register
		</button>
	</form>

	<p class="mt-4 text-center">
		Already have an account?
		<a href="/auth/login" class="text-blue-500 hover:underline">Login</a>
	</p>
</div>
