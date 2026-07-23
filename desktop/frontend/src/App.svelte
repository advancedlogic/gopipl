<script>
  import { onMount } from "svelte";
  import {
    store,
    refreshStatus,
    refreshConversations,
    wire,
  } from "./lib/store.svelte.js";
  import Setup from "./components/Setup.svelte";
  import Sidebar from "./components/Sidebar.svelte";
  import Conversation from "./components/Conversation.svelte";
  import Empty from "./components/Empty.svelte";
  import Toasts from "./components/Toasts.svelte";

  onMount(async () => {
    wire();
    await refreshStatus();
    if (store.status?.ready) await refreshConversations();
  });
</script>

<Toasts />

{#if store.loading}
  <div class="splash">
    <div class="logo">PIPL</div>
    <div class="faint">loading…</div>
  </div>
{:else if store.status?.needsSetup}
  <Setup />
{:else if store.status?.error && !store.status?.ready}
  <div class="splash">
    <div class="logo">PIPL</div>
    <div class="err">{store.status.error}</div>
  </div>
{:else}
  <div class="shell">
    <Sidebar />
    {#if store.activeName}
      {#key store.activeName}
        <Conversation />
      {/key}
    {:else}
      <Empty />
    {/if}
  </div>
{/if}

<style>
  .shell {
    display: grid;
    grid-template-columns: 300px 1fr;
    height: 100%;
    background: var(--bg);
  }
  .splash {
    height: 100%;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 8px;
  }
  .logo {
    font-family: var(--mono);
    font-weight: 700;
    letter-spacing: 0.35em;
    font-size: 26px;
    color: var(--accent);
  }
  .err {
    color: var(--danger);
    max-width: 460px;
    text-align: center;
    font-family: var(--mono);
    font-size: 12px;
  }
</style>
