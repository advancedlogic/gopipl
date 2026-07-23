// Central reactive store (Svelte 5 runes). Holds the loaded status, the
// conversation list, the open conversation and its messages, and a small
// toast queue for the honest-limitation notices the engine returns. All
// mutation goes through the exported actions so components stay declarative.
import { api, on } from "./api.js";

export const store = $state({
  loading: true,
  status: null, // StatusInfo from the Go side
  conversations: [],
  activeName: null, // name of the open conversation
  messages: [],
  toasts: [], // {id, kind, text}
  pins: [], // outstanding TOFU fingerprint notices
});

let toastSeq = 0;

export function toast(text, kind = "info") {
  const id = ++toastSeq;
  store.toasts = [...store.toasts, { id, kind, text }];
  const ttl = kind === "error" ? 9000 : 6000;
  setTimeout(() => dismissToast(id), ttl);
  return id;
}

export function dismissToast(id) {
  store.toasts = store.toasts.filter((t) => t.id !== id);
}

export function activeConversation() {
  return store.conversations.find((c) => c.name === store.activeName) || null;
}

export async function refreshStatus() {
  try {
    store.status = await api.status();
  } catch (e) {
    store.status = { error: String(e) };
  } finally {
    store.loading = false;
  }
}

export async function refreshConversations() {
  if (!store.status?.ready) return;
  try {
    store.conversations = (await api.conversations()) || [];
  } catch (e) {
    toast(String(e), "error");
  }
}

export async function openConversation(name) {
  store.activeName = name;
  await refreshMessages();
}

export async function refreshMessages() {
  if (!store.activeName) {
    store.messages = [];
    return;
  }
  try {
    store.messages = (await api.messages(store.activeName)) || [];
  } catch (e) {
    toast(String(e), "error");
  }
}

async function drainPins() {
  try {
    const pins = (await api.drainPins()) || [];
    if (pins.length) {
      store.pins = [...store.pins, ...pins];
      for (const p of pins) {
        toast(
          `First contact with ${p.handle} — fingerprint ${p.fingerprint}. Verify it out of band.`,
          "warn"
        );
      }
    }
  } catch (_) {
    /* best-effort */
  }
}

export function dismissPin(handle) {
  store.pins = store.pins.filter((p) => p.handle !== handle);
}

// wire subscribes to backend events so the UI stays live without polling
// from components. Called once from App on mount.
export function wire() {
  on("pipl:changed", async () => {
    await Promise.all([refreshConversations(), refreshMessages(), drainPins()]);
  });
  on("pipl:tick", async () => {
    await Promise.all([refreshConversations(), refreshMessages()]);
  });
  on("pipl:pin", () => drainPins());
  on("pipl:notice", (n) => {
    if (n?.text) toast(n.text, n.kind || "info");
  });
}
