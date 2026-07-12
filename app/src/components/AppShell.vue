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

const vault = useVaultStore();
const showAdd = ref(false);
</script>

<template>
  <div class="app">
    <BrandBar />
    <TopBar @new-item="showAdd = true" />
    <SideNav />
    <ItemList />
    <WatchtowerView v-if="vault.filter === 'watchtower'" />
    <ItemDetail v-else />
  </div>
  <AddItemDialog v-if="showAdd" @close="showAdd = false" />
</template>
