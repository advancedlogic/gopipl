// Thin wrapper over the Wails-generated bindings for the Go App. Keeping
// every backend call behind this module means the components never import
// the generated paths directly, and there is one place to adapt if the
// binding surface changes. Every call here forwards to internal/chat on the
// Go side — no crypto or key material ever crosses into JS.
import * as App from "../../wailsjs/go/main/App";
import { EventsOn } from "../../wailsjs/runtime/runtime";

export const api = {
  status: () => App.Status(),
  setup: (handle, server) => App.Setup(handle, server),
  reannounce: () => App.Reannounce(),

  conversations: () => App.Conversations(),
  messages: (conv) => App.Messages(conv),
  hidden: (conv) => App.Hidden(conv),

  newConversation: (name, dir, withHandles) =>
    App.NewConversation(name, dir, withHandles),
  joinByInvite: (name, code) => App.JoinByInvite(name, code),
  joinByFolder: (name, dir) => App.JoinByFolder(name, dir),
  invite: (conv) => App.Invite(conv),

  send: (conv, body, recipients, forceSeparate) =>
    App.Send(conv, body, recipients, forceSeparate),

  revokeFrom: (conv, objectId, handle) =>
    App.RevokeFrom(conv, objectId, handle),
  hide: (conv, objectId) => App.Hide(conv, objectId),
  unhide: (conv, objectId) => App.Unhide(conv, objectId),
  revokeAll: (conv, objectId) => App.RevokeAll(conv, objectId),

  drainPins: () => App.DrainPins(),
};

// on subscribes to a backend event; returns an unsubscribe function.
export function on(event, handler) {
  return EventsOn(event, handler);
}
