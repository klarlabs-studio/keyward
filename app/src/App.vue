<script setup lang="ts">
import { useVaultStore } from '@/stores/vault';
import UnlockView from '@/components/UnlockView.vue';
import AppShell from '@/components/AppShell.vue';
import ToastHost from '@/components/ToastHost.vue';
import EmergencyKitDialog from '@/components/EmergencyKitDialog.vue';

const vault = useVaultStore();
</script>

<template>
  <UnlockView v-if="vault.locked" />
  <AppShell v-else />
  <!-- One-time Emergency Kit reveal right after first-run vault creation. -->
  <EmergencyKitDialog
    v-if="vault.freshSecretKey"
    :secret-key="vault.freshSecretKey"
    first-run
    @close="vault.acknowledgeKit()"
  />
  <ToastHost />
</template>

<!-- Shared stylesheet for the whole vault surface. The palette lives in
     tokens.css (imported globally); this only maps the prototype's structural
     classes onto those tokens, so components stay markup-only. -->
<style>
.app {
  display: grid;
  grid-template-columns: 236px 340px 1fr;
  grid-template-rows: 56px 1fr;
  height: 100vh;
  grid-template-areas: 'brand top top' 'nav list detail';
}
@media (max-width: 900px) {
  .app {
    grid-template-columns: 1fr;
    grid-template-rows: 56px auto 1fr;
    grid-template-areas: 'top' 'list' 'detail';
  }
  .brand {
    display: none;
  }
  /* The category rail becomes an off-canvas drawer, opened by the top-bar menu. */
  .nav {
    position: fixed;
    top: 0;
    left: 0;
    bottom: 0;
    width: min(280px, 82vw);
    z-index: 60;
    border-right: 1px solid var(--line);
    transform: translateX(-100%);
    transition: transform 0.22s ease;
    will-change: transform;
  }
  .nav.open {
    transform: translateX(0);
    box-shadow: var(--shadow);
  }
  .nav-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(10, 16, 15, 0.45);
    z-index: 55;
  }
}
/* Phones: tighten the top bar and drop non-essential chrome so ~8 controls +
   search never overflow. The pill's status is still in the Sync dialog. */
@media (max-width: 640px) {
  .top {
    gap: 0.3rem;
    padding: 0 0.55rem;
  }
  .vault-pill {
    display: none;
  }
  .btn-add .label {
    display: none;
  }
  .btn-add {
    padding: 0.44rem 0.55rem;
  }
}
/* On desktop the drawer machinery is inert. */
.nav-backdrop {
  display: none;
}
@media (max-width: 900px) {
  .nav-backdrop {
    display: block;
  }
}

/* brand */
.brand {
  grid-area: brand;
  display: flex;
  align-items: center;
  gap: 0.55rem;
  padding: 0 1.1rem;
  border-right: 1px solid var(--line);
  border-bottom: 1px solid var(--line);
  background: var(--surface-2);
}
.mark {
  width: 26px;
  height: 26px;
  border-radius: 8px;
  background: linear-gradient(135deg, var(--accent), var(--accent-ink));
  display: grid;
  place-items: center;
  color: #fff;
  box-shadow: var(--shadow);
}
.mark svg {
  width: 15px;
  height: 15px;
}
.brand b {
  font-weight: 650;
  letter-spacing: -0.02em;
  font-size: 0.98rem;
}
.brand span {
  color: var(--faint);
  font-size: 0.72rem;
  margin-left: auto;
  font-weight: 600;
  letter-spacing: 0.03em;
}

/* top bar */
.top {
  grid-area: top;
  display: flex;
  align-items: center;
  gap: 0.7rem;
  padding: 0 1rem;
  border-bottom: 1px solid var(--line);
  background: var(--surface);
}
.search {
  flex: 1;
  max-width: 460px;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  background: var(--surface-2);
  border: 1px solid var(--line);
  border-radius: 9px;
  padding: 0.42rem 0.7rem;
}
.search:focus-within {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-soft);
}
.search input {
  flex: 1;
  min-width: 0; /* let the search shrink instead of pushing the top bar wider */
  border: 0;
  background: none;
  outline: none;
  color: var(--ink);
  font-size: 0.9rem;
}
.search svg {
  width: 15px;
  height: 15px;
  color: var(--faint);
  flex: none;
}
.top .spacer {
  flex: 1;
}
.vault-pill {
  display: flex;
  align-items: center;
  gap: 0.45rem;
  padding: 0.32rem 0.6rem;
  border: 1px solid var(--line);
  border-radius: 999px;
  font-size: 0.8rem;
  color: var(--muted);
}
.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--accent);
}
.btn-add {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  background: var(--accent);
  color: #fff;
  padding: 0.44rem 0.8rem;
  border-radius: 9px;
  font-weight: 600;
  font-size: 0.85rem;
  box-shadow: var(--shadow);
}
.btn-add:hover {
  background: var(--accent-ink);
}
.icon-btn {
  width: 34px;
  height: 34px;
  border-radius: 8px;
  display: grid;
  place-items: center;
  color: var(--muted);
}
.icon-btn:hover {
  background: var(--surface-2);
  color: var(--ink);
}

/* nav */
.nav {
  grid-area: nav;
  border-right: 1px solid var(--line);
  background: var(--surface-2);
  padding: 0.7rem 0.6rem;
  overflow-y: auto;
}
.nav .grp {
  font-size: 0.68rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--faint);
  font-weight: 700;
  padding: 0.9rem 0.6rem 0.35rem;
}
.navitem {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  width: 100%;
  text-align: left;
  padding: 0.5rem 0.6rem;
  border-radius: 8px;
  color: var(--muted);
  font-weight: 500;
}
.navitem:hover {
  background: var(--surface);
  color: var(--ink);
}
.navitem.active {
  background: var(--accent-soft);
  color: var(--accent-ink);
  font-weight: 600;
}
.navitem svg {
  width: 16px;
  height: 16px;
  flex: none;
}
.navitem .count {
  margin-left: auto;
  font-size: 0.75rem;
  color: var(--faint);
  font-variant-numeric: tabular-nums;
}
.navitem.active .count {
  color: var(--accent-ink);
}
.wt-chip {
  margin-top: 0.5rem;
  display: flex;
  align-items: center;
  gap: 0.55rem;
  padding: 0.55rem 0.6rem;
  border-radius: 10px;
  background: var(--weak-soft);
  color: var(--weak);
  font-weight: 600;
  font-size: 0.82rem;
  width: 100%;
  text-align: left;
}
.wt-chip.active {
  outline: 2px solid var(--weak);
  outline-offset: -2px;
}
.wt-chip .n {
  margin-left: auto;
  background: var(--weak);
  color: #fff;
  border-radius: 999px;
  padding: 0.02rem 0.42rem;
  font-size: 0.72rem;
}

/* list */
.list {
  grid-area: list;
  border-right: 1px solid var(--line);
  background: var(--surface);
  overflow-y: auto;
}
.list-head {
  position: sticky;
  top: 0;
  background: var(--surface);
  padding: 0.7rem 1rem 0.5rem;
  border-bottom: 1px solid var(--line);
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
}
.list-head h2 {
  margin: 0;
  font-size: 1rem;
  letter-spacing: -0.01em;
}
.list-head span {
  color: var(--faint);
  font-size: 0.78rem;
  font-variant-numeric: tabular-nums;
}
.empty {
  padding: 2rem 1rem;
  text-align: center;
  color: var(--faint);
  font-size: 0.85rem;
}
.row {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.6rem 1rem;
  width: 100%;
  text-align: left;
  border-bottom: 1px solid var(--line);
}
.row:hover {
  background: var(--surface-2);
}
.row.active {
  background: var(--accent-soft);
}
.avatar {
  width: 34px;
  height: 34px;
  border-radius: 9px;
  flex: none;
  display: grid;
  place-items: center;
  font-weight: 700;
  font-size: 0.82rem;
  color: #fff;
}
.row .meta {
  min-width: 0;
}
.row .t {
  font-weight: 600;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.row .s {
  color: var(--muted);
  font-size: 0.8rem;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.row .fav {
  margin-left: auto;
  color: var(--warn);
  flex: none;
}
.cat-badge {
  flex: none;
  font-size: 0.66rem;
  color: var(--faint);
  border: 1px solid var(--line-strong);
  border-radius: 5px;
  padding: 0.03rem 0.34rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

/* detail */
.detail {
  grid-area: detail;
  overflow-y: auto;
  background: var(--paper);
  padding: 1.4rem clamp(1rem, 3vw, 2.4rem);
}
.card {
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 16px;
  box-shadow: var(--shadow);
  max-width: 640px;
  margin: 0 auto;
  overflow: hidden;
}
.card-hd {
  display: flex;
  align-items: center;
  gap: 0.9rem;
  padding: 1.3rem 1.4rem;
  border-bottom: 1px solid var(--line);
}
.card-hd .avatar {
  width: 48px;
  height: 48px;
  border-radius: 12px;
  font-size: 1.05rem;
}
.card-hd h1 {
  margin: 0;
  font-size: 1.25rem;
  letter-spacing: -0.02em;
}
.card-hd .sub {
  color: var(--muted);
  font-size: 0.85rem;
}
.card-hd .hd-actions {
  margin-left: auto;
  display: flex;
  gap: 0.25rem;
}
.field {
  display: flex;
  align-items: center;
  gap: 0.9rem;
  padding: 0.85rem 1.4rem;
  border-top: 1px solid var(--line);
}
.field:first-child {
  border-top: 0;
}
.field .lbl {
  width: 96px;
  flex: none;
  color: var(--faint);
  font-size: 0.74rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  font-weight: 600;
}
.field .val {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.field .val.mono {
  font-family: var(--mono);
  font-size: 0.9rem;
  letter-spacing: 0.02em;
}
.field .act {
  display: flex;
  gap: 0.25rem;
  margin-left: auto;
}
.mini {
  width: 30px;
  height: 30px;
  border-radius: 7px;
  display: grid;
  place-items: center;
  color: var(--muted);
}
.mini:hover {
  background: var(--surface-2);
  color: var(--accent-ink);
}
.mini svg {
  width: 15px;
  height: 15px;
}
a.link {
  color: var(--accent-ink);
  text-decoration: none;
}
a.link:hover {
  text-decoration: underline;
}

/* totp */
.totp {
  display: flex;
  align-items: center;
  gap: 0.7rem;
}
.totp .code {
  font-family: var(--mono);
  font-size: 1.15rem;
  letter-spacing: 0.16em;
  font-weight: 600;
}
.ring {
  width: 26px;
  height: 26px;
  flex: none;
  transform: rotate(-90deg);
}
.ring circle {
  fill: none;
  stroke-width: 3;
}
.ring .bg {
  stroke: var(--line-strong);
}
.ring .fg {
  stroke: var(--accent);
  stroke-linecap: round;
  transition: stroke-dashoffset 1s linear;
}

.tags {
  display: flex;
  gap: 0.4rem;
  flex-wrap: wrap;
}
.tag {
  font-size: 0.72rem;
  background: var(--surface-2);
  border: 1px solid var(--line);
  border-radius: 999px;
  padding: 0.1rem 0.55rem;
  color: var(--muted);
}

/* watchtower */
.wt {
  max-width: 640px;
  margin: 0 auto;
}
.wt-top {
  display: flex;
  align-items: center;
  gap: 1.2rem;
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 16px;
  padding: 1.3rem 1.4rem;
  box-shadow: var(--shadow);
}
.gauge {
  width: 76px;
  height: 76px;
  flex: none;
  transform: rotate(-90deg);
}
.gauge circle {
  fill: none;
  stroke-width: 8;
}
.gauge .bg {
  stroke: var(--line);
}
.gauge .fg {
  stroke-linecap: round;
}
.wt-score {
  display: flex;
  flex-direction: column;
}
.wt-score b {
  font-size: 1.6rem;
  letter-spacing: -0.02em;
}
.wt-score span {
  color: var(--muted);
  font-size: 0.85rem;
}
.issue {
  display: flex;
  align-items: center;
  gap: 0.8rem;
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 0.75rem 1rem;
  margin-top: 0.7rem;
}
.issue .pill {
  font-size: 0.68rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  padding: 0.14rem 0.5rem;
  border-radius: 6px;
  flex: none;
}
.pill.weak {
  background: var(--weak-soft);
  color: var(--weak);
}
.pill.reused {
  background: var(--warn-soft);
  color: var(--warn);
}
.pill.missing {
  background: var(--warn-soft);
  color: var(--warn);
}
.issue .txt {
  min-width: 0;
}
.issue .txt b {
  font-weight: 600;
}
.issue .txt div {
  color: var(--muted);
  font-size: 0.82rem;
}
.issue button {
  margin-left: auto;
  color: var(--accent-ink);
  font-weight: 600;
  font-size: 0.82rem;
  flex: none;
}
.wt h3 {
  margin: 1.4rem 0 0.2rem;
  font-size: 0.78rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--faint);
}

/* strength bar */
.strength {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.bar {
  flex: 1;
  max-width: 120px;
  height: 5px;
  border-radius: 3px;
  background: var(--line);
  overflow: hidden;
}
.bar i {
  display: block;
  height: 100%;
  border-radius: 3px;
}
.strength small {
  font-size: 0.72rem;
  color: var(--muted);
}

.share {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin: 1.1rem auto 0;
  max-width: 640px;
  color: var(--muted);
  font-size: 0.82rem;
}
.avstack {
  display: flex;
}
.avstack span {
  width: 24px;
  height: 24px;
  border-radius: 50%;
  margin-left: -7px;
  border: 2px solid var(--surface);
  display: grid;
  place-items: center;
  font-size: 0.62rem;
  font-weight: 700;
  color: #fff;
}
</style>
