<script>
  import {
    store,
    refreshConversations,
    toast,
  } from "../lib/store.svelte.js";
  import { api } from "../lib/api.js";

  let handle = $state("");
  let server = $state("http://127.0.0.1:8737");
  let noServer = $state(false);
  let busy = $state(false);

  async function submit() {
    if (!handle.trim() || busy) return;
    busy = true;
    try {
      const s = await api.setup(handle.trim(), noServer ? "" : server.trim());
      store.status = s;
      if (s.error) {
        // Identity created but registration failed — recoverable.
        toast(s.error, "warn");
      }
      if (s.ready) await refreshConversations();
    } catch (e) {
      toast(String(e), "error");
    } finally {
      busy = false;
    }
  }
</script>

<div class="wrap">
  <form
    class="card"
    onsubmit={(e) => {
      e.preventDefault();
      submit();
    }}
  >
    <div class="logo">PIPL</div>
    <p class="lede">
      Peer-to-peer chat where every message is an encrypted, signed file you can
      revoke. Pick a handle to create this device's identity — its keys never
      leave your machine.
    </p>

    <label>
      <span>Handle</span>
      <input
        bind:value={handle}
        placeholder="alice"
        autocomplete="off"
        spellcheck="false"
      />
    </label>

    <label class:disabled={noServer}>
      <span>Coordination server</span>
      <input
        bind:value={server}
        disabled={noServer}
        placeholder="http://127.0.0.1:8737"
        spellcheck="false"
      />
    </label>

    <label class="check">
      <input type="checkbox" bind:checked={noServer} />
      <span
        >Run without a server (folder-only conversations, no live pings)</span
      >
    </label>

    <button class="primary" type="submit" disabled={!handle.trim() || busy}>
      {busy ? "Creating identity…" : "Create identity"}
    </button>

    <p class="foot faint">
      The server is keyless: it stores ciphertext it cannot read and an identity
      directory. Verify peer fingerprints out of band on first contact.
    </p>
  </form>
</div>

<style>
  .wrap {
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    background: radial-gradient(
      120% 120% at 50% 0%,
      #171c27 0%,
      var(--bg) 60%
    );
  }
  .card {
    width: 420px;
    background: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 28px;
    box-shadow: var(--shadow);
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  .logo {
    font-family: var(--mono);
    font-weight: 700;
    letter-spacing: 0.35em;
    font-size: 22px;
    color: var(--accent);
    text-align: center;
  }
  .lede {
    margin: 0;
    color: var(--text-dim);
    line-height: 1.5;
    font-size: 13px;
  }
  label {
    display: flex;
    flex-direction: column;
    gap: 6px;
    font-size: 12px;
    color: var(--text-dim);
  }
  label.disabled {
    opacity: 0.5;
  }
  label.check {
    flex-direction: row;
    align-items: center;
    gap: 9px;
    cursor: pointer;
  }
  label.check input {
    width: auto;
  }
  .foot {
    margin: 0;
    font-size: 11px;
    line-height: 1.5;
  }
</style>
