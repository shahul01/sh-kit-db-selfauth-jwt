<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';

	type Todo = {
		id: number;
		title: string;
		completed: boolean;
		created_at: string;
	};

	let todos: Todo[] = [];
	let newTodoTitle = '';
	let loading = false;
	let error = '';
	let mounted = false;

	onMount(() => {
		mounted = true;
		loadTodos();
	});

	/**
	 * Loads todos with proper error handling
	 */
	async function loadTodos(): Promise<void> {
		if (!mounted) return;

		try {
			error = '';
			const response = await fetch('/api/todos');

			if (!response.ok) {
				if (response.status === 401) {
					// Unauthorized, redirect to login
					await goto('/auth/login');
					return;
				}
				throw new Error(`HTTP ${response.status}: ${response.statusText}`);
			}

			const data = await response.json();
			if (Array.isArray(data)) {
				todos = data;
			} else {
				throw new Error('Invalid response format');
			}
		} catch (fetchError) {
			console.error('Failed to load todos:', fetchError);
			error = 'Failed to load todos. Please try again.';
		}
	}

	/**
	 * Validates todo title
	 */
	function validateTodoTitle(title: string): string | null {
		const trimmed = title.trim();
		if (!trimmed) {
			return 'Todo title cannot be empty';
		}
		if (trimmed.length > 500) {
			return 'Todo title must be less than 500 characters';
		}
		return null;
	}

	/**
	 * Adds a new todo with validation and error handling
	 */
	async function addTodo(): Promise<void> {
		if (!mounted || loading) return;

		// Validate input
		const validationError = validateTodoTitle(newTodoTitle);
		if (validationError) {
			error = validationError;
			return;
		}

		loading = true;
		error = '';

		try {
			const response = await fetch('/api/todos', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ title: newTodoTitle.trim() })
			});

			if (!response.ok) {
				if (response.status === 401) {
					await goto('/auth/login');
					return;
				}
				const errorData = await response.json().catch(() => ({}));
				throw new Error(errorData.error || `HTTP ${response.status}`);
			}

			// Clear input and reload todos
			newTodoTitle = '';
			await loadTodos();
		} catch (fetchError) {
			console.error('Failed to add todo:', fetchError);
			error = fetchError instanceof Error ? fetchError.message : 'Failed to add todo';
		} finally {
			loading = false;
		}
	}

	/**
	 * Toggles todo completion status
	 */
	async function toggleTodo(todo: Todo): Promise<void> {
		if (!mounted || loading) return;

		loading = true;
		error = '';

		try {
			const response = await fetch(`/api/todos/${todo.id}`, {
				method: 'PATCH',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ completed: !todo.completed })
			});

			if (!response.ok) {
				if (response.status === 401) {
					await goto('/auth/login');
					return;
				}
				const errorData = await response.json().catch(() => ({}));
				throw new Error(errorData.error || `HTTP ${response.status}`);
			}

			await loadTodos();
		} catch (fetchError) {
			console.error('Failed to toggle todo:', fetchError);
			error = fetchError instanceof Error ? fetchError.message : 'Failed to update todo';
		} finally {
			loading = false;
		}
	}

	/**
	 * Deletes a todo with confirmation
	 */
	async function deleteTodo(id: number): Promise<void> {
		if (!mounted || loading) return;

		// Simple confirmation
		if (!confirm('Are you sure you want to delete this todo?')) {
			return;
		}

		loading = true;
		error = '';

		try {
			const response = await fetch(`/api/todos/${id}`, {
				method: 'DELETE'
			});

			if (!response.ok) {
				if (response.status === 401) {
					await goto('/auth/login');
					return;
				}
				const errorData = await response.json().catch(() => ({}));
				throw new Error(errorData.error || `HTTP ${response.status}`);
			}

			await loadTodos();
		} catch (fetchError) {
			console.error('Failed to delete todo:', fetchError);
			error = fetchError instanceof Error ? fetchError.message : 'Failed to delete todo';
		} finally {
			loading = false;
		}
	}

	/**
	 * Handles logout with proper error handling
	 */
	async function logout(): Promise<void> {
		if (!mounted || loading) return;

		loading = true;

		try {
			const response = await fetch('/auth/logout', {
				method: 'POST'
			});

			// Even if logout fails, redirect to login
			await goto('/auth/login');
		} catch (fetchError) {
			console.error('Logout error:', fetchError);
			// Still redirect to login on error
			await goto('/auth/login');
		} finally {
			loading = false;
		}
	}

	/**
	 * Handles Enter key press in todo input
	 */
	function handleKeydown(event: KeyboardEvent): void {
		if (event.key === 'Enter' && !loading) {
			addTodo();
		}
	}

	// Reactive computed values
	$: completedCount = todos.filter((todo) => todo.completed).length;
	$: totalCount = todos.length;
	$: pendingCount = totalCount - completedCount;
</script>

<svelte:window on:keydown={handleKeydown} />

<div class="mx-auto max-w-2xl p-4">
	<div class="mb-4 flex items-center justify-between">
		<h1 class="text-2xl font-bold">Todo List</h1>
		<button
			on:click={logout}
			disabled={loading}
			class="rounded bg-red-500 px-4 py-2 text-white hover:bg-red-600 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 disabled:cursor-not-allowed disabled:bg-gray-400"
		>
			{loading ? 'Logging out...' : 'Logout'}
		</button>
	</div>

	{#if error}
		<div class="mb-4 rounded bg-red-100 p-3 text-red-700" role="alert">
			{error}
			<button
				on:click={() => (error = '')}
				class="ml-2 text-red-800 hover:text-red-900"
				aria-label="Dismiss error"
			>
				×
			</button>
		</div>
	{/if}

	<!-- Todo Stats -->
	<div class="mb-4 rounded bg-gray-100 p-3 text-sm">
		<span class="font-medium">Total todos: {totalCount}</span>
		{#if totalCount}
			• <span class="text-green-600">Completed: {completedCount}</span>
			• <span class="text-blue-600">Pending: {pendingCount}</span>
		{/if}
	</div>

	<!-- Add Todo Form -->
	<form on:submit|preventDefault={addTodo} class="mb-6">
		<div class="flex gap-2">
			<input
				type="text"
				bind:value={newTodoTitle}
				placeholder="Add new todo (max 500 characters)"
				disabled={loading}
				maxlength="500"
				class="flex-1 rounded border p-2 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500 disabled:bg-gray-100"
				aria-label="New todo title"
			/>
			<button
				type="submit"
				disabled={loading || !newTodoTitle.trim()}
				class="rounded bg-blue-500 px-4 py-2 text-white hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:cursor-not-allowed disabled:bg-gray-400"
			>
				{loading ? 'Adding...' : 'Add'}
			</button>
		</div>
	</form>

	<!-- Todos List -->
	{#if todos.length === 0}
		<div class="py-8 text-center text-gray-500">
			<p>No todos yet. Add one above to get started!</p>
		</div>
	{:else}
		<ul class="space-y-2">
			{#each todos as todo (todo.id)}
				<li class="flex items-center gap-2 rounded border p-3 transition-colors hover:bg-gray-50">
					<input
						type="checkbox"
						checked={todo.completed}
						on:change={() => toggleTodo(todo)}
						disabled={loading}
						class="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
						aria-label={`Mark "${todo.title}" as ${todo.completed ? 'incomplete' : 'complete'}`}
					/>
					<span
						class:line-through={todo.completed}
						class:text-gray-500={todo.completed}
						class="flex-1 break-words"
					>
						{todo.title}
					</span>
					<button
						on:click={() => deleteTodo(todo.id)}
						disabled={loading}
						class="text-red-500 hover:text-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 disabled:text-gray-400"
						aria-label={`Delete "${todo.title}"`}
					>
						Delete
					</button>
				</li>
			{/each}
		</ul>
	{/if}
</div>
