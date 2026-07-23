<script>
  import {
    store,
    openConversation,
    refreshConversations,
  } from "../lib/store.svelte.js";
  import NewConversation from "./NewConversation.svelte";
  import JoinConversation from "./JoinConversation.svelte";
  import { api } from "../lib/api.js";
  import { toast } from "../lib/store.svelte.js";

  let modal = $state(null); // "new" | "join" | null

  async function reannounce() {
    try {
      toast(await api.reannounce(), "info");
    } catch (e) {
      toast(String(e), "error");
    }
  }

  function initial(c) {
    return (c.name || "?").slice(0, 2).toUpperCase();
  }

  function when(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    const now = new Date();
    const sameDay = d.toDateString() === now.toDateString();
    return sameDay
      ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
      : d.toLocaleDateString([], { month: "short", day: "numeric" });
  }

  function preview(c) {
    if (c.readError) return "unreadable — " + c.readError;
    if (!c.count) return "no messages yet";
    const who = c.lastFrom === store.status?.handle ? "you" : c.lastFrom;
    return `${who} · ${c.count} message${c.count === 1 ? "" : "s"}`;
  }
</script>

<aside>
  <header>
    <div class="me">
      <div class="brand mono">PIPL</div>
      <div class="who">
        <span class="handle">{store.status?.handle}</span>
        <span class="fp mono faint" title="your identity fingerprint"
          >{store.status?.fingerprint}</span
        >
      </div>
    </div>
    <div class="acts">
      <button class="primary sm" onclick={() => (modal = "new")}>New</button>
      <button class="sm" onclick={() => (modal = "join")}>Join</button>
    </div>
  </header>

  <div class="list">
    {#if store.conversations.length === 0}
      <div class="none faint">
        No conversations yet. <b>New</b> creates one; <b>Join</b> accepts an invite
        code or shared folder.
      </div>
    {/if}
    {#each store.conversations as c (c.name)}
      <button
        class="row"
        class:active={c.name === store.activeName}
        onclick={() => openConversation(c.name)}
      >
        <div class="avatar" class:relay={c.relay}>{initial(c)}</div>
        <div class="meta">
          <div class="top">
            <span class="name">{c.name}</span>
            <span class="time faint">{when(c.lastAt)}</span>
          </div>
          <div class="sub faint" class:err={c.readError}>{preview(c)}</div>
        </div>
        <div class="tag mono faint" title={c.relay ? "relayed through the server" : "shared folder"}>
          {c.relay ? "relay" : "folder"}
        </div>
      </button>
    {/each}
  </div>

  <footer>
    <span class="faint mono srv" title={store.status?.home}>
      {store.status?.server || "no server"}
    </span>
    {#if store.status?.server}
      <button
        class="ghost announce"
        onclick={reannounce}
        title="Re-register your identity with the server so peers can find you (needed after a server restart)"
        >Re-announce</button
      >
    {/if}
  </footer>
</aside>

{#if modal === "new"}
  <NewConversation onclose={() => (modal = null)} />
{:else if modal === "join"}
  <JoinConversation onclose={() => (modal = null)} />
{/if}

<style>
  aside {
    display: grid;
    grid-template-rows: auto 1fr auto;
    height: 100%;
    background: var(--bg-1);
    border-right: 1px solid var(--border);
    min-width: 0;
  }
  header {
    padding: 14px 14px 12px;
    border-bottom: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    gap: 12px;
    -webkit-app-region: drag;
  }
  .acts {
    -webkit-app-region: no-drag;
    display: flex;
    gap: 8px;
  }
  .me {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .brand {
    font-weight: 700;
    letter-spacing: 0.25em;
    color: var(--accent);
    font-size: 15px;
  }
  .who {
    display: flex;
    flex-direction: column;
    line-height: 1.25;
    min-width: 0;
  }
  .handle {
    font-weight: 600;
  }
  .fp {
    font-size: 11px;
  }
  .sm {
    padding: 5px 12px;
    font-size: 13px;
    flex: 1;
  }
  .list {
    overflow-y: auto;
    padding: 6px;
  }
  .none {
    padding: 22px 14px;
    font-size: 12px;
    line-height: 1.55;
  }
  .row {
    display: grid;
    grid-template-columns: auto 1fr auto;
    align-items: center;
    gap: 11px;
    width: 100%;
    text-align: left;
    border: none;
    background: none;
    border-radius: 8px;
    padding: 9px 10px;
  }
  .row:hover {
    background: var(--bg-2);
  }
  .row.active {
    background: var(--bg-2);
    box-shadow: inset 3px 0 0 var(--accent);
  }
  .avatar {
    width: 34px;
    height: 34px;
    border-radius: 9px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: var(--mono);
    font-size: 12px;
    font-weight: 700;
    background: var(--accent-dim);
    color: #fff;
  }
  .avatar.relay {
    background: #3a4a6b;
  }
  .meta {
    min-width: 0;
  }
  .top {
    display: flex;
    justify-content: space-between;
    gap: 8px;
  }
  .name {
    font-weight: 600;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .time {
    font-size: 11px;
    white-space: nowrap;
  }
  .sub {
    font-size: 12px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .sub.err {
    color: var(--danger);
  }
  .tag {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  footer {
    padding: 6px 8px 6px 12px;
    border-top: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }
  .srv {
    font-size: 10px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .announce {
    font-size: 11px;
    padding: 3px 8px;
    flex-shrink: 0;
    color: var(--text-dim);
  }
  .announce:hover {
    color: var(--text);
  }
</style>
