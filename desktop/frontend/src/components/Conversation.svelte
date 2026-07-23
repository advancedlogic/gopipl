<script>
  import { tick } from "svelte";
  import { api } from "../lib/api.js";
  import {
    store,
    activeConversation,
    refreshMessages,
    refreshConversations,
    toast,
  } from "../lib/store.svelte.js";
  import MessageActions from "./MessageActions.svelte";

  const conv = $derived(activeConversation());
  const self = $derived(store.status?.handle);

  // Recipient selection. A Set of selected "others". Whole-roster (all
  // selected) uses the group key; a strict subset forces per-recipient keys.
  // Empty selection means "nobody" and must never be sent — the send button
  // is disabled, matching the engine's refusal.
  let selected = $state(new Set());
  let forceSeparate = $state(false);
  let body = $state("");
  let sending = $state(false);
  let showRecipients = $state(false);
  let threadEl = $state(null);

  const others = $derived(conv?.others ?? []);
  const everyone = $derived(
    others.length > 0 && selected.size === others.length
  );
  const nobody = $derived(others.length > 0 && selected.size === 0);
  const subset = $derived(!everyone && !nobody);
  const willSeparate = $derived(subset || forceSeparate);

  // Reset selection to the whole roster whenever the conversation changes.
  $effect(() => {
    const list = conv?.others ?? [];
    selected = new Set(list);
    forceSeparate = false;
    body = "";
  });

  // Keep the thread pinned to the newest message.
  $effect(() => {
    store.messages.length;
    tick().then(() => {
      if (threadEl) threadEl.scrollTop = threadEl.scrollHeight;
    });
  });

  function toggle(h) {
    const next = new Set(selected);
    next.has(h) ? next.delete(h) : next.add(h);
    selected = next;
  }
  function selectAll() {
    selected = new Set(others);
  }
  function selectNone() {
    selected = new Set();
  }

  const audienceLabel = $derived(
    nobody
      ? "no recipients selected"
      : everyone && !forceSeparate
        ? "whole roster · shared group key"
        : everyone && forceSeparate
          ? "whole roster · per-recipient keys (forced)"
          : `${selected.size} of ${others.length} · per-recipient keys`
  );

  async function send() {
    if (!body.trim() || nobody || sending) return;
    sending = true;
    try {
      const recipients = everyone ? [] : [...selected];
      const res = await api.send(
        conv.name,
        body.trim(),
        recipients,
        forceSeparate
      );
      body = "";
      await refreshMessages();
      await refreshConversations();
      if (res.note) toast(res.note, "info");
    } catch (e) {
      toast(String(e), "error");
    } finally {
      sending = false;
    }
  }

  function onKey(e) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  }

  async function copyInvite() {
    try {
      const code = await api.invite(conv.name);
      await navigator.clipboard.writeText(code);
      toast("Invite code copied to clipboard.", "info");
    } catch (e) {
      toast(String(e), "error");
    }
  }

  function fmtTime(iso) {
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
  function fmtDay(iso) {
    const d = new Date(iso);
    return d.toLocaleDateString([], {
      weekday: "long",
      month: "long",
      day: "numeric",
    });
  }
  // Group messages by day for date separators.
  const grouped = $derived.by(() => {
    const out = [];
    let lastDay = null;
    for (const m of store.messages) {
      const day = new Date(m.sentAt).toDateString();
      if (day !== lastDay) {
        out.push({ sep: true, day: m.sentAt, key: "sep-" + day });
        lastDay = day;
      }
      out.push({ sep: false, m, key: m.objectId });
    }
    return out;
  });
</script>

<section class="conv">
  <header>
    <div class="title">
      <h2>{conv?.name}</h2>
      <span class="members faint">
        {conv?.members?.join(", ")}
        {#if conv?.relay}· relay{:else}· folder{/if}
      </span>
    </div>
    <div class="head-acts">
      {#if conv?.relay}
        <button class="sm" onclick={copyInvite}>Copy invite</button>
      {/if}
      <button
        class="sm"
        class:on={showRecipients}
        onclick={() => (showRecipients = !showRecipients)}
        title="choose who each message goes to">Recipients</button
      >
    </div>
  </header>

  <div class="body" class:with-panel={showRecipients}>
    <div class="thread" bind:this={threadEl}>
      {#if store.messages.length === 0}
        <div class="empty-thread faint">
          No messages yet. What you type goes to
          <b>{audienceLabel}</b>.
        </div>
      {/if}
      {#each grouped as g (g.key)}
        {#if g.sep}
          <div class="daysep"><span>{fmtDay(g.day)}</span></div>
        {:else}
          <div class="msg" class:mine={g.m.mine}>
            <div class="bubble">
              <div class="mhead">
                <span class="from">{g.m.mine ? "you" : g.m.from}</span>
                <span class="time faint">{fmtTime(g.m.sentAt)}</span>
                {#if g.m.owned}
                  <MessageActions message={g.m} {conv} />
                {/if}
              </div>
              <div class="text">{g.m.body}</div>
              {#if g.m.mine && g.m.audience?.length}
                <div class="aud faint" title="this send used per-recipient keys">
                  → {g.m.audience.join(", ")}
                </div>
              {/if}
            </div>
          </div>
        {/if}
      {/each}
    </div>

    {#if showRecipients}
      <aside class="panel">
        <div class="panel-head">
          <span>Recipients</span>
          <div class="mini">
            <button class="ghost" onclick={selectAll} disabled={everyone}
              >all</button
            >
            <button class="ghost" onclick={selectNone} disabled={nobody}
              >none</button
            >
          </div>
        </div>
        <div class="recips">
          {#each others as h}
            <label class="recip">
              <input
                type="checkbox"
                checked={selected.has(h)}
                onchange={() => toggle(h)}
              />
              <span>{h}</span>
            </label>
          {/each}
          {#if others.length === 0}
            <div class="faint small">You are the only member.</div>
          {/if}
        </div>
        <label class="force">
          <input type="checkbox" bind:checked={forceSeparate} />
          <span>Force per-recipient keys (individually revocable)</span>
        </label>
        <div class="model">
          <div class="model-name mono" class:sep-mode={willSeparate}>
            {willSeparate ? "SEPARATE" : "GROUP"}
          </div>
          <p class="faint small">
            {#if willSeparate}
              Each recipient gets a personal key; excluded members get no slot
              at all — the exclusion is cryptographic. Any recipient can be
              hard-revoked later without re-granting the rest.
            {:else}
              One shared group key, one slot regardless of group size.
              Revoking a single member later needs a group-key rotation
              (roadmap) — or hide the message from everyone.
            {/if}
          </p>
        </div>
      </aside>
    {/if}
  </div>

  <footer class="composer">
    <div class="badge mono" class:sep-mode={willSeparate} class:none={nobody}>
      {audienceLabel}
    </div>
    <div class="input-row">
      <textarea
        bind:value={body}
        onkeydown={onKey}
        rows="1"
        placeholder={nobody
          ? "Select at least one recipient…"
          : "Write a message — Enter to send, Shift+Enter for a newline"}
        disabled={nobody}
      ></textarea>
      <button
        class="primary send"
        onclick={send}
        disabled={!body.trim() || nobody || sending}
      >
        {sending ? "…" : "Send"}
      </button>
    </div>
  </footer>
</section>

<style>
  .conv {
    display: grid;
    grid-template-rows: auto 1fr auto;
    height: 100%;
    min-width: 0;
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 13px 18px;
    border-bottom: 1px solid var(--border);
    -webkit-app-region: drag;
  }
  .title {
    min-width: 0;
  }
  h2 {
    margin: 0;
    font-size: 16px;
  }
  .members {
    font-size: 12px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    display: block;
  }
  .head-acts {
    display: flex;
    gap: 8px;
    -webkit-app-region: no-drag;
  }
  .sm {
    padding: 5px 11px;
    font-size: 13px;
  }
  .sm.on {
    border-color: var(--accent);
    background: var(--bg-2);
  }

  .body {
    display: grid;
    grid-template-columns: 1fr;
    overflow: hidden;
    min-height: 0;
  }
  .body.with-panel {
    grid-template-columns: 1fr 260px;
  }
  .thread {
    overflow-y: auto;
    padding: 18px 18px 8px;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .empty-thread {
    margin: auto;
    text-align: center;
    max-width: 360px;
    line-height: 1.6;
    font-size: 13px;
  }
  .daysep {
    text-align: center;
    margin: 14px 0 8px;
    font-size: 11px;
    color: var(--text-faint);
    position: relative;
  }
  .daysep span {
    background: var(--bg);
    padding: 0 10px;
  }
  .msg {
    display: flex;
    margin: 2px 0;
  }
  .msg.mine {
    justify-content: flex-end;
  }
  .bubble {
    max-width: 68%;
    background: var(--bg-2);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 8px 12px 9px;
  }
  .msg.mine .bubble {
    background: var(--accent-dim);
    border-color: var(--accent);
  }
  .mhead {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 2px;
  }
  .from {
    font-weight: 600;
    font-size: 12px;
  }
  .time {
    font-size: 11px;
  }
  .mhead :global(.wrap) {
    margin-left: auto;
  }
  .text {
    white-space: pre-wrap;
    word-break: break-word;
    line-height: 1.45;
    user-select: text;
  }
  .aud {
    margin-top: 4px;
    font-size: 11px;
    font-family: var(--mono);
  }

  .panel {
    border-left: 1px solid var(--border);
    background: var(--bg-1);
    overflow-y: auto;
    padding: 14px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .panel-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-weight: 600;
    font-size: 13px;
  }
  .mini {
    display: flex;
    gap: 2px;
  }
  .mini button {
    padding: 2px 8px;
    font-size: 11px;
  }
  .recips {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .recip {
    display: flex;
    align-items: center;
    gap: 9px;
    padding: 6px 8px;
    border-radius: 7px;
    cursor: pointer;
    font-size: 13px;
  }
  .recip:hover {
    background: var(--bg-2);
  }
  .recip input {
    width: auto;
  }
  .force {
    display: flex;
    align-items: center;
    gap: 9px;
    font-size: 12px;
    color: var(--text-dim);
    cursor: pointer;
    padding-top: 6px;
    border-top: 1px solid var(--border);
    line-height: 1.35;
  }
  .force input {
    width: auto;
    flex-shrink: 0;
  }
  .model {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 10px;
  }
  .model-name {
    font-weight: 700;
    letter-spacing: 0.12em;
    font-size: 12px;
    color: var(--good);
  }
  .model-name.sep-mode {
    color: var(--warn);
  }
  .small {
    font-size: 11px;
    line-height: 1.5;
  }
  .model p {
    margin: 5px 0 0;
  }

  .composer {
    border-top: 1px solid var(--border);
    padding: 10px 14px 14px;
    background: var(--bg-1);
  }
  .badge {
    display: inline-block;
    font-size: 10px;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    color: var(--good);
    margin-bottom: 7px;
  }
  .badge.sep-mode {
    color: var(--warn);
  }
  .badge.none {
    color: var(--danger);
  }
  .input-row {
    display: flex;
    gap: 10px;
    align-items: flex-end;
  }
  .input-row textarea {
    min-height: 42px;
    max-height: 160px;
    line-height: 1.4;
    padding: 11px;
  }
  .send {
    height: 42px;
    padding: 0 20px;
    flex-shrink: 0;
  }
</style>
