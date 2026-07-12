// A tiny reactive toast singleton shared across the app. `toast(msg)` pushes a
// transient message; `copyText(v)` writes to the clipboard and confirms with a
// toast — used by every copy button in the vault.

import { ref } from 'vue';

export interface ToastItem {
  id: number;
  msg: string;
}

const toasts = ref<ToastItem[]>([]);
let seq = 0;

export function toast(msg: string): void {
  const id = (seq += 1);
  toasts.value.push({ id, msg });
  window.setTimeout(() => {
    toasts.value = toasts.value.filter((t) => t.id !== id);
  }, 1300);
}

/** Copy `text` to the clipboard and confirm with a toast. */
export async function copyText(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    toast('Copied to clipboard');
  } catch {
    toast('Copy failed');
  }
}

export function useToast() {
  return { toasts, toast, copyText };
}
