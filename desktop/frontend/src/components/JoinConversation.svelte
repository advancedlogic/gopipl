<script>
  import Modal from "./Modal.svelte";
  import { api } from "../lib/api.js";
  import {
    refreshConversations,
    openConversation,
    toast,
  } from "../lib/store.svelte.js";

  let { onclose } = $props();

  let mode = $state("invite"); // "invite" | "folder"
  let name = $state("");
  let code = $state("");
  let dir = $state("");
  let busy = $state(false);

  const canSubmit = $derived(
    !!name.trim() &&
      ((mode === "invite" && !!code.trim()) ||
        (mode === "folder" && !!dir.trim()))
  );

  async function join() {
    if (!canSubmit || busy) return;
    busy = true;
    try {
      if (mode === "invite") {
        await api.joinByInvite(name.trim(), code.trim());
      } else {
        await api.joinByFolder(name.trim(), dir.trim());
      }
      await refreshConversations();
      await openConversation(name.trim());
      toast("Joined. Verify the creator's fingerprint out of band.", "info");
      onclose();
    } catch (e) {
      toast(String(e), "error");
    } finally {
      busy = false;
    }
  }
</script>

<Modal title="Join a conversation" {onclose}>
  <form
    class="stack"
    onsubmit={(e) => {
      e.preventDefault();
      join();
    }}
  >
    <div class="tabs">
      <button
        type="button"
        class:sel={mode === "invite"}
        onclick={() => (mode = "invite")}>Invite code</button
      >
      <button
        type="button"
        class:sel={mode === "folder"}
        onclick={() => (mode = "folder")}>Shared folder</button
      >
    </div>

    <label>
      <span>Local name for this conversation</span>
      <input bind:value={name} placeholder="team" autocomplete="off" />
    </label>

    {#if mode === "invite"}
      <label>
        <span>Invite code (starts with <code>pipl1:</code>)</span>
        <textarea
          class="mono"
          rows="4"
          bind:value={code}
          placeholder="pipl1:eyJpIjoi…"
          spellcheck="false"
        ></textarea>
      </label>
    {:else}
      <label>
        <span>Shared folder path</span>
        <input
          bind:value={dir}
          placeholder="C:\\path\\to\\shared"
          spellcheck="false"
        />
      </label>
    {/if}

    <div class="row-btns">
      <button type="button" onclick={onclose}>Cancel</button>
      <button class="primary" type="submit" disabled={!canSubmit || busy}>
        {busy ? "Joining…" : "Join"}
      </button>
    </div>
  </form>
</Modal>

<style>
  .stack {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .tabs {
    display: flex;
    gap: 8px;
  }
  .tabs button {
    flex: 1;
  }
  .tabs button.sel {
    border-color: var(--accent);
    background: var(--bg-2);
  }
  label {
    display: flex;
    flex-direction: column;
    gap: 6px;
    font-size: 12px;
    color: var(--text-dim);
  }
  code {
    font-family: var(--mono);
    color: var(--good);
  }
  .row-btns {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }
</style>
