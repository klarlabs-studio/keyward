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

const vault = useVaultStore();
const showAdd = ref(false);
const showKit = ref(false);
const showImport = ref(false);
</script>

<template>
  <div class="app">
    <BrandBar />
    <TopBar @new-item="showAdd = true" @view-kit="showKit = true" @import="showImport = true" />
    <SideNav />
    <ItemList />
    <WatchtowerView v-if="vault.filter === 'watchtower'" />
    <ItemDetail v-else />
  </div>
  <AddItemDialog v-if="showAdd" @close="showAdd = false" />
  <ImportDialog v-if="showImport" @close="showImport = false" />
  <EmergencyKitDialog
    v-if="showKit && vault.secretKey"
    :secret-key="vault.secretKey"
    @close="showKit = false"
  />
</template>
