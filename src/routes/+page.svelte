<script lang="ts">
	import { page } from '$app/stores';
</script>

<div class="mx-auto max-w-2xl p-4">
	<h1 class="mb-4 text-2xl font-bold">Welcome to Todo App</h1>

	{#if $page.data.userId}
		<a href="/todos" class="text-blue-500 hover:underline">Go to Todos</a>
	{:else}
		<div class="space-y-2">
			<a href="/auth/login" class="block text-blue-500 hover:underline">Login</a>
			<a href="/auth/register" class="block text-blue-500 hover:underline">Register</a>
		</div>
	{/if}
</div>
