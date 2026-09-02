<template>
  <view class="page">
    <view class="card">
      <text class="title">长列表 · {{ items.length }} 条</text>
      <text class="sub">网络: {{ netStatus }}</text>
      <button size="mini" @click="fetchPing">uni.request 探测</button>
    </view>
    <scroll-view scroll-y class="list" @scrolltolower="loadMore">
      <view v-for="item in items" :key="item.id" class="row">
        <text class="row-id">#{{ item.id }}</text>
        <text class="row-title">{{ item.title }}</text>
      </view>
      <view class="footer">{{ loading ? '加载中…' : '上拉加载更多' }}</view>
    </scroll-view>
  </view>
</template>

<script setup>
import { ref } from 'vue'
import { onShow, onPullDownRefresh } from '@dcloudio/uni-app'
import { probeShow } from '../../utils/probe.js'

const items = ref([])
const page = ref(0)
const loading = ref(false)
const netStatus = ref('-')

onShow(() => probeShow('list'))

function seed(n) {
  const start = items.value.length
  const more = []
  for (let i = 0; i < n; i++) {
    const id = start + i + 1
    more.push({ id, title: `Weex row ${id} · protector smoke ${Date.now() % 10000}` })
  }
  items.value = items.value.concat(more)
}

seed(200)

function loadMore() {
  if (loading.value) return
  loading.value = true
  setTimeout(() => {
    seed(40)
    page.value += 1
    loading.value = false
    console.log('[XOP-DEMO] list loadMore page=', page.value, 'size=', items.value.length)
  }, 200)
}

onPullDownRefresh(() => {
  items.value = []
  seed(200)
  uni.stopPullDownRefresh()
  console.log('[XOP-DEMO] list pullDownRefresh')
})

function fetchPing() {
  netStatus.value = 'requesting…'
  uni.request({
    url: 'https://httpbin.org/get',
    method: 'GET',
    timeout: 8000,
    success: (res) => {
      netStatus.value = `ok status=${res.statusCode}`
      console.log('[XOP-DEMO] request ok', res.statusCode)
    },
    fail: (err) => {
      netStatus.value = `fail ${err.errMsg || err}`
      console.warn('[XOP-DEMO] request fail', err)
    }
  })
}
</script>

<style scoped>
.page { height: 100vh; display: flex; flex-direction: column; }
.card { margin: 24rpx; padding: 24rpx; background: #fff; border-radius: 16rpx; }
.title { font-size: 32rpx; font-weight: 700; }
.sub { display: block; margin: 8rpx 0 12rpx; color: #666; font-size: 24rpx; }
.list { flex: 1; height: 0; padding: 0 24rpx 24rpx; }
.row { background: #fff; margin-bottom: 12rpx; padding: 24rpx; border-radius: 12rpx; display: flex; gap: 16rpx; }
.row-id { color: #1976d2; font-weight: 700; width: 100rpx; }
.row-title { flex: 1; color: #333; font-size: 26rpx; }
.footer { text-align: center; color: #999; padding: 24rpx; font-size: 24rpx; }
</style>
