<script setup lang="ts">
// The unlocked 3-pane vault: brand + nav / item list / detail (or Watchtower),
// with the top bar spanning the top row. Owns the add-item dialog state.

import { ref } from 'vue';
import { useVaultStore } from '@/stores/vault';
import { useShareStore } from '@/stores/share';
import BrandBar from './BrandBar.vue';
import TopBar from './TopBar.vue';
import SideNav from './SideNav.vue';
import ItemList from './ItemList.vue';
import ItemDetail from './ItemDetail.vue';
import WatchtowerView from './WatchtowerView.vue';
import FamilyList from './FamilyList.vue';
import FamilyDetail from './FamilyDetail.vue';
import AddItemDialog from './AddItemDialog.vue';
import EmergencyKitDialog from './EmergencyKitDialog.vue';
import ImportDialog from './ImportDialog.vue';
import ExportDialog from './ExportDialog.vue';
import SyncDialog from './SyncDialog.vue';
import ShareDialog from './ShareDialog.vue';

const vault = useVaultStore();
const share = useShareStore();
const showAdd = ref(false);
const showKit = ref(false);
const showImport = ref(false);
const showExport = ref(false);
const showSync = ref(false);
const showShare = ref(false);
// Mobile drawer for the category rail (hidden by the responsive layout otherwise).
const navOpen = ref(false);
</script>

<template>
  <div class="app" :class="{ 'nav-open': navOpen }">
    <BrandBar />
    <TopBar
      @new-item="share.mainGroupId ? (showShare = true) : (showAdd = true)"
      @view-kit="showKit = true"
      @import="showImport = true"
      @export="showExport = true"
      @sync="showSync = true"
      @share="showShare = true"
      @toggle-nav="navOpen = !navOpen"
    />
    <div v-if="navOpen" class="nav-backdrop" @click="navOpen = false"></div>
    <SideNav :open="navOpen" @navigate="navOpen = false" />
    <template v-if="share.mainGroupId">
      <FamilyList @manage="showShare = true" />
      <FamilyDetail />
    </template>
    <template v-else>
      <ItemList />
      <WatchtowerView v-if="vault.filter === 'watchtower'" />
      <ItemDetail v-else />
    </template>
  </div>
  <AddItemDialog v-if="showAdd" @close="showAdd = false" />
  <ImportDialog v-if="showImport" @close="showImport = false" />
  <ExportDialog v-if="showExport" @close="showExport = false" />
  <SyncDialog v-if="showSync" @close="showSync = false" />
  <ShareDialog v-if="showShare" @close="showShare = false" />
  <EmergencyKitDialog
    v-if="showKit && vault.secretKey"
    :secret-key="vault.secretKey"
    @close="showKit = false"
  />
</template>
