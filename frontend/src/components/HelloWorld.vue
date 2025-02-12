<template>
  <v-container class="fill-height">
    <v-row>
      <v-card>
        <v-btn @click="fetchServices">Fetch Services</v-btn>
        <v-data-table :items="services"></v-data-table>
      </v-card>
    </v-row>
    <v-row>
      <v-card>
        <v-btn @click="checkAdmin">Check Admin</v-btn>
        <v-chip v-if="isLocalAdmin">Local Admin</v-chip>
      </v-card>
    </v-row>
  </v-container>
</template>

<script setup lang="ts">

  import { ref } from 'vue'

  const services = ref([])

  const fetchServices = async () => {
    const response = await fetch('http://3.99.128.213:3000/services')
    services.value = await response.json()
  }

  const isLocalAdmin = ref(false)

  const checkAdmin = async () => {
    const response = await fetch('http://3.99.128.213:3000/is_local_admin')
    isLocalAdmin.value = await response.json()
  }



</script>
