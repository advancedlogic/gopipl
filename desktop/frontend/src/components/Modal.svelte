<script>
  let { title, onclose, children } = $props();

  function onkey(e) {
    if (e.key === "Escape") onclose?.();
  }
</script>

<svelte:window onkeydown={onkey} />

<div class="backdrop" onclick={onclose} role="presentation">
  <div
    class="modal"
    onclick={(e) => e.stopPropagation()}
    role="dialog"
    aria-modal="true"
    aria-label={title}
    tabindex="-1"
  >
    <div class="head">
      <h3>{title}</h3>
      <button class="ghost x" onclick={onclose} aria-label="close">×</button>
    </div>
    <div class="body">
      {@render children?.()}
    </div>
  </div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    background: rgba(6, 8, 12, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 40;
    animation: fade 0.12s ease-out;
  }
  .modal {
    width: 460px;
    max-width: calc(100vw - 40px);
    max-height: calc(100vh - 60px);
    overflow: auto;
    background: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
  }
  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 18px;
    border-bottom: 1px solid var(--border);
  }
  h3 {
    margin: 0;
    font-size: 15px;
  }
  .x {
    font-size: 20px;
    line-height: 1;
    padding: 0 6px;
    color: var(--text-faint);
  }
  .body {
    padding: 18px;
  }
  @keyframes fade {
    from {
      opacity: 0;
    }
    to {
      opacity: 1;
    }
  }
</style>
