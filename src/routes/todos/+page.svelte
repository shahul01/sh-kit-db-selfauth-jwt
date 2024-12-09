<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';

	type Todo = {
		id: number;
		title: string;
		completed: boolean;
	};

	let todos: Todo[] = [];
	let newTodoTitle = '';

	async function loadTodos() {
		const response = await fetch('/api/todos');
		if (response.ok) {
			todos = await response.json();
		}
	}

	async function addTodo() {
		if (!newTodoTitle.trim()) return;

		const response = await fetch('/api/todos', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ title: newTodoTitle })
		});

		if (response.ok) {
			newTodoTitle = '';
			await loadTodos();
		}
	}

	async function toggleTodo(todo: Todo) {
		await fetch(`/api/todos/${todo.id}`, {
			method: 'PATCH',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ completed: !todo.completed })
		});
		await loadTodos();
	}

	async function deleteTodo(id: number) {
		await fetch(`/api/todos/${id}`, { method: 'DELETE' });
		await loadTodos();
	}

	async function logout() {
		const response = await fetch('/auth/logout', {
			method: 'POST'
		});

		if (response.ok) {
			goto('/auth/login');
		}
	}

	onMount(loadTodos);
</script>

<div class="mx-auto max-w-2xl p-4">
	<button on:click={logout} class="mt-4 rounded bg-red-500 p-2 text-white hover:bg-red-600">
		Logout
	</button>
	<h1 class="mb-4 text-2xl font-bold">Todo List</h1>

	<form on:submit|preventDefault={addTodo} class="mb-6">
		<div class="flex gap-2">
			<input
				type="text"
				bind:value={newTodoTitle}
				placeholder="Add new todo"
				class="flex-1 rounded border p-2"
			/>
			<button type="submit" class="rounded bg-blue-500 px-4 py-2 text-white">Add</button>
		</div>
	</form>

	<ul class="space-y-2">
		{#each todos as todo (todo.id)}
			<li class="flex items-center gap-2 rounded border p-2">
				<input type="checkbox" checked={todo.completed} on:change={() => toggleTodo(todo)} />
				<span class:line-through={todo.completed}>{todo.title}</span>
				<button on:click={() => deleteTodo(todo.id)} class="ml-auto text-red-500"> Delete </button>
			</li>
		{/each}
	</ul>
</div>
