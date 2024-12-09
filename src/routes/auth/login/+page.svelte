<script lang="ts">
	import { goto } from '$app/navigation';

	let username = '';
	let password = '';
	let error = '';

	async function handleSubmit() {
		const response = await fetch('/auth/login', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ username, password })
		});

		const data = await response.json();

		if (response.ok) {
			goto('/todos');
		} else {
			error = data.error || 'Login failed';
		}
	}
</script>

<div class="mx-auto max-w-md p-6">
	<h1 class="mb-6 text-2xl font-bold">Login</h1>

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

		<button type="submit" class="w-full rounded bg-blue-500 p-2 text-white hover:bg-blue-600">
			Login
		</button>
	</form>

	<p class="mt-4 text-center">
		Don't have an account?
		<a href="/auth/register" class="text-blue-500 hover:underline">Register</a>
	</p>
</div>
