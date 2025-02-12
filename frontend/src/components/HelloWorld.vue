<template>
  <v-container class="fill-height">
    <v-btn @click="fetchServices">Fetch Services</v-btn>
    <v-data-table :items="services"></v-data-table>
  </v-container>
</template>

<script setup lang="ts">

  import { ref } from 'vue'

  const services = ref([])

  const fetchServices = async () => {
    const response = await fetch('http://3.99.128.213:3000/services')
    services.value = await response.json()
  }

</script>
