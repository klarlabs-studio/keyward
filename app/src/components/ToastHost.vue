<script setup lang="ts">
import { useToast } from '@/composables/useToast';

const { toasts } = useToast();
</script>

<template>
  <div class="toast-host" aria-live="polite">
    <div v-for="t in toasts" :key="t.id" class="toast show">{{ t.msg }}</div>
  </div>
</template>

<style scoped>
.toast-host {
  position: fixed;
  bottom: 22px;
  left: 50%;
  transform: translateX(-50%);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.4rem;
  z-index: 50;
  pointer-events: none;
}
.toast {
  background: var(--ink);
  color: var(--paper);
  padding: 0.55rem 1rem;
  border-radius: 10px;
  font-size: 0.85rem;
  font-weight: 500;
  box-shadow: var(--shadow);
  transform: translateY(20px);
  opacity: 0;
  transition: 0.22s;
}
.toast.show {
  opacity: 1;
  transform: translateY(0);
}
</style>
