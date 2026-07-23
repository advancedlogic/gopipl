<script>
  import { api } from "../lib/api.js";
  import { store, refreshMessages, toast } from "../lib/store.svelte.js";

  let { message, conv } = $props();

  let open = $state(false);
  let busy = $state(false);

  // Recipients this peer can still revoke: only meaningful for its own
  // separate sends, where the audience is known.
  const revocable = $derived(message.mode === "separate" ? message.audience : []);

  async function run(fn, ...args) {
    busy = true;
    try {
      const note = await fn(...args);
      await refreshMessages();
      if (note) toast(note, "info");
    } catch (e) {
      toast(String(e), "error");
    } finally {
      busy = false;
      open = false;
    }
  }

  function close() {
    open = false;
  }
</script>

<div class="wrap">
  <button
    class="ghost trigger"
    title="message actions"
    onclick={(e) => {
      e.stopPropagation();
      open = !open;
    }}>⋯</button
  >

  {#if open}
    <div class="menu" role="menu">
      <button
        role="menuitem"
        disabled={busy}
        onclick={() => run(api.hide, conv.name, message.objectId)}
        >Hide from everyone</button
      >
      <button
        role="menuitem"
        disabled={busy}
        onclick={() => run(api.unhide, conv.name, message.objectId)}
        >Unhide</button
      >

      {#if message.mode === "separate" && revocable.length}
        <div class="sep faint">Revoke recipient</div>
        {#each revocable as h}
          <button
            role="menuitem"
            class="danger-item"
            disabled={busy}
            onclick={() => run(api.revokeFrom, conv.name, message.objectId, h)}
            >Revoke {h}</button
          >
        {/each}
      {:else if message.mode === "group"}
        <div class="note faint">
          Group send — revoking one member needs a group-key rotation
          (roadmap). Hide it, or send a subset next time.
        </div>
      {/if}

      <div class="sep"></div>
      <button
        role="menuitem"
        class="danger-item"
        disabled={busy}
        onclick={() => run(api.revokeAll, conv.name, message.objectId)}
        >Delete permanently</button
      >
    </div>
    <div class="scrim" onclick={close} role="presentation"></div>
  {/if}
</div>

<style>
  .wrap {
    position: relative;
  }
  .trigger {
    padding: 2px 7px;
    font-size: 16px;
    line-height: 1;
    color: var(--text-faint);
    border-radius: 6px;
  }
  .trigger:hover {
    color: var(--text);
  }
  .scrim {
    position: fixed;
    inset: 0;
    z-index: 9;
  }
  .menu {
    position: absolute;
    top: 100%;
    right: 0;
    margin-top: 4px;
    z-index: 10;
    min-width: 220px;
    background: var(--bg-2);
    border: 1px solid var(--border);
    border-radius: 9px;
    box-shadow: var(--shadow);
    padding: 5px;
    display: flex;
    flex-direction: column;
    gap: 1px;
  }
  .menu button {
    border: none;
    background: none;
    text-align: left;
    border-radius: 6px;
    padding: 8px 10px;
    font-size: 13px;
  }
  .menu button:hover:not(:disabled) {
    background: var(--bg-3);
  }
  .menu button.danger-item {
    color: var(--danger);
  }
  .menu button.danger-item:hover:not(:disabled) {
    background: var(--danger-dim);
    color: #fff;
  }
  .sep {
    height: 1px;
    background: var(--border);
    margin: 4px 2px;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  .sep.faint {
    height: auto;
    background: none;
    padding: 6px 10px 2px;
  }
  .note {
    font-size: 11px;
    line-height: 1.45;
    padding: 6px 10px;
    max-width: 220px;
  }
</style>
