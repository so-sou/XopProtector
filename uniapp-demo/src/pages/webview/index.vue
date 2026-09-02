<template>
  <view class="page">
    <view class="card">
      <text class="title">内嵌 WebView</text>
      <text class="sub">验证多进程 WebView；若整页白但 Tab 在，对照 Weex 页是否也白。</text>
    </view>
    <web-view src="https://www.example.com"></web-view>
  </view>
</template>

<script setup>
import { onShow } from '@dcloudio/uni-app'
import { probeShow } from '../../utils/probe.js'
onShow(() => probeShow('webview'))
</script>

<style scoped>
.page { height: 100vh; }
.card { margin: 24rpx; padding: 24rpx; background: #fff; border-radius: 16rpx; }
.title { font-size: 32rpx; font-weight: 700; }
.sub { display: block; margin-top: 8rpx; color: #666; font-size: 24rpx; }
</style>
