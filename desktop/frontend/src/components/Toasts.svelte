<script>
  import { store, dismissToast } from "../lib/store.svelte.js";
</script>

<div class="toasts">
  {#each store.toasts as t (t.id)}
    <div class="toast {t.kind}" role="status">
      <span>{t.text}</span>
      <button class="x" onclick={() => dismissToast(t.id)} aria-label="dismiss"
        >×</button
      >
    </div>
  {/each}
</div>

<style>
  .toasts {
    position: fixed;
    bottom: 16px;
    right: 16px;
    z-index: 50;
    display: flex;
    flex-direction: column;
    gap: 8px;
    max-width: 420px;
  }
  .toast {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    background: var(--bg-2);
    border: 1px solid var(--border);
    border-left-width: 3px;
    border-radius: 8px;
    padding: 11px 12px;
    box-shadow: var(--shadow);
    font-size: 13px;
    line-height: 1.4;
    animation: rise 0.15s ease-out;
  }
  .toast.info {
    border-left-color: var(--accent);
  }
  .toast.warn {
    border-left-color: var(--warn);
  }
  .toast.error {
    border-left-color: var(--danger);
  }
  .toast .x {
    border: none;
    background: none;
    padding: 0 2px;
    font-size: 18px;
    line-height: 1;
    color: var(--text-faint);
  }
  .toast .x:hover {
    color: var(--text);
    background: none;
  }
  @keyframes rise {
    from {
      transform: translateY(8px);
      opacity: 0;
    }
    to {
      transform: translateY(0);
      opacity: 1;
    }
  }
</style>
