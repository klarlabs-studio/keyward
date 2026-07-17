<script setup lang="ts">
// The unlocked 3-pane vault: brand + nav / item list / detail (or Watchtower),
// with the top bar spanning the top row. Owns the add-item dialog state.

import { ref } from 'vue';
import { useVaultStore } from '@/stores/vault';
import BrandBar from './BrandBar.vue';
import TopBar from './TopBar.vue';
import SideNav from './SideNav.vue';
import ItemList from './ItemList.vue';
import ItemDetail from './ItemDetail.vue';
import WatchtowerView from './WatchtowerView.vue';
import AddItemDialog from './AddItemDialog.vue';
import EmergencyKitDialog from './EmergencyKitDialog.vue';
import ImportDialog from './ImportDialog.vue';
import ExportDialog from './ExportDialog.vue';
import SyncDialog from './SyncDialog.vue';

const vault = useVaultStore();
const showAdd = ref(false);
const showKit = ref(false);
const showImport = ref(false);
const showExport = ref(false);
const showSync = ref(false);
// Mobile drawer for the category rail (hidden by the responsive layout otherwise).
const navOpen = ref(false);
</script>

<template>
  <div class="app" :class="{ 'nav-open': navOpen }">
    <BrandBar />
    <TopBar
      @new-item="showAdd = true"
      @view-kit="showKit = true"
      @import="showImport = true"
      @export="showExport = true"
      @sync="showSync = true"
      @toggle-nav="navOpen = !navOpen"
    />
    <div v-if="navOpen" class="nav-backdrop" @click="navOpen = false"></div>
    <SideNav :open="navOpen" @navigate="navOpen = false" />
    <ItemList />
    <WatchtowerView v-if="vault.filter === 'watchtower'" />
    <ItemDetail v-else />
  </div>
  <AddItemDialog v-if="showAdd" @close="showAdd = false" />
  <ImportDialog v-if="showImport" @close="showImport = false" />
  <ExportDialog v-if="showExport" @close="showExport = false" />
  <SyncDialog v-if="showSync" @close="showSync = false" />
  <EmergencyKitDialog
    v-if="showKit && vault.secretKey"
    :secret-key="vault.secretKey"
    @close="showKit = false"
  />
</template>
