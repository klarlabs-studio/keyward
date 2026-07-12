<script setup lang="ts">
// Live one-time-code field: real RFC-6238 code from the WASM core plus a
// countdown ring. Ticks once a second and cleans up its interval on unmount or
// when the secret changes.

import { computed, onBeforeUnmount, ref, watch } from 'vue';
import { totpCode, totpSecondsRemaining } from '@/lib/passbook';
import { copyText } from '@/composables/useToast';

const props = defineProps<{ secret: string }>();

const RADIUS = 11;
const CIRC = 2 * Math.PI * RADIUS;

const code = ref<string>('------');
const remaining = ref<number>(30);

let timer: number | null = null;

const display = computed(() =>
  code.value.length === 6 ? `${code.value.slice(0, 3)} ${code.value.slice(3)}` : '— — —',
);
const dashOffset = computed(() => CIRC * (1 - remaining.value / 30));

async function tick(): Promise<void> {
  const [next, rem] = await Promise.all([totpCode(props.secret), totpSecondsRemaining()]);
  code.value = next ?? '------';
  remaining.value = rem;
}

function start(): void {
  stop();
  void tick();
  timer = window.setInterval(() => void tick(), 1000);
}

function stop(): void {
  if (timer !== null) {
    window.clearInterval(timer);
    timer = null;
  }
}

watch(() => props.secret, start, { immediate: true });
onBeforeUnmount(stop);
</script>

<template>
  <div class="field">
    <div class="lbl">One-time code</div>
    <div class="val">
      <div class="totp">
        <svg class="ring" viewBox="0 0 26 26">
          <circle class="bg" cx="13" cy="13" r="11" />
          <circle
            class="fg"
            cx="13"
            cy="13"
            r="11"
            :style="{ strokeDasharray: CIRC, strokeDashoffset: dashOffset }"
          />
        </svg>
        <span class="code">{{ display }}</span>
      </div>
    </div>
    <div class="act">
      <button class="mini" title="Copy" @click="copyText(code)">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="9" y="9" width="11" height="11" rx="2" />
          <path d="M5 15V5a2 2 0 0 1 2-2h10" />
        </svg>
      </button>
    </div>
  </div>
</template>
