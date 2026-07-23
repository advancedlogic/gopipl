<script>
  import Modal from "./Modal.svelte";
  import { api } from "../lib/api.js";
  import {
    refreshConversations,
    openConversation,
    toast,
  } from "../lib/store.svelte.js";

  let { onclose } = $props();

  let name = $state("");
  let withText = $state("");
  let relay = $state(true); // relay by default: no shared folder needed
  let dir = $state("");
  let busy = $state(false);
  let invite = $state(""); // shown after creation for a relay conversation

  const members = $derived(
    withText
      .split(/[,\s]+/)
      .map((s) => s.trim())
      .filter(Boolean)
  );

  async function create() {
    if (!name.trim() || members.length === 0 || busy) return;
    busy = true;
    try {
      await api.newConversation(
        name.trim(),
        relay ? "" : dir.trim(),
        members
      );
      await refreshConversations();
      if (relay) {
        invite = await api.invite(name.trim());
        toast("Conversation created. Share the invite code below.", "info");
      } else {
        toast("Conversation created in the shared folder.", "info");
        await openConversation(name.trim());
        onclose();
      }
    } catch (e) {
      toast(String(e), "error");
    } finally {
      busy = false;
    }
  }

  async function copyInvite() {
    try {
      await navigator.clipboard.writeText(invite);
      toast("Invite code copied.", "info");
    } catch (_) {
      /* clipboard may be unavailable */
    }
  }

  function done() {
    openConversation(name.trim());
    onclose();
  }
</script>

<Modal title="New conversation" {onclose}>
  {#if invite}
    <div class="stack">
      <p class="dim">
        Send this invite code to <b>{members.join(", ")}</b>. It carries the
        roster but <b>no key</b> — a stolen code reads nothing. They join with
        it under any local name.
      </p>
      <textarea class="mono code" rows="4" readonly>{invite}</textarea>
      <div class="row-btns">
        <button onclick={copyInvite}>Copy code</button>
        <button class="primary" onclick={done}>Open conversation</button>
      </div>
    </div>
  {:else}
    <form
      class="stack"
      onsubmit={(e) => {
        e.preventDefault();
        create();
      }}
    >
      <label>
        <span>Name</span>
        <input bind:value={name} placeholder="team" autocomplete="off" />
      </label>

      <label>
        <span>Members (handles, comma or space separated)</span>
        <input bind:value={withText} placeholder="bob, carol" autocomplete="off" />
      </label>

      <div class="transport">
        <button
          type="button"
          class:sel={relay}
          onclick={() => (relay = true)}
        >
          <b>Relay</b><span class="faint"
            >through the server — no shared folder needed</span
          >
        </button>
        <button
          type="button"
          class:sel={!relay}
          onclick={() => (relay = false)}
        >
          <b>Shared folder</b><span class="faint"
            >a path both peers can reach (Drive/Dropbox works)</span
          >
        </button>
      </div>

      {#if !relay}
        <label>
          <span>Shared folder path</span>
          <input
            bind:value={dir}
            placeholder="C:\\path\\to\\shared"
            spellcheck="false"
          />
        </label>
      {/if}

      <p class="faint hint">
        The whole roster shares one group key by default. To make individually
        revocable messages, pick a subset of recipients when you send.
      </p>

      <div class="row-btns">
        <button type="button" onclick={onclose}>Cancel</button>
        <button
          class="primary"
          type="submit"
          disabled={!name.trim() || members.length === 0 || busy}
        >
          {busy ? "Creating…" : "Create"}
        </button>
      </div>
    </form>
  {/if}
</Modal>

<style>
  .stack {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  label {
    display: flex;
    flex-direction: column;
    gap: 6px;
    font-size: 12px;
    color: var(--text-dim);
  }
  .transport {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
  }
  .transport button {
    display: flex;
    flex-direction: column;
    gap: 3px;
    text-align: left;
    padding: 10px;
    font-size: 12px;
  }
  .transport button.sel {
    border-color: var(--accent);
    background: var(--bg-2);
  }
  .transport .faint {
    font-size: 11px;
    line-height: 1.35;
  }
  .row-btns {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }
  .hint {
    font-size: 11px;
    line-height: 1.5;
    margin: 0;
  }
  .code {
    color: var(--good);
    word-break: break-all;
  }
  p {
    margin: 0;
    line-height: 1.5;
    font-size: 13px;
  }
</style>
