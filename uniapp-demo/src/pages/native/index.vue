<template>
  <view class="page">
    <view class="card">
      <text class="title">原生 / 存储能力</text>
      <text class="mono">{{ log }}</text>
      <button class="btn" type="primary" @click="writeStorage">写 Storage</button>
      <button class="btn" @click="readStorage">读 Storage</button>
      <button class="btn" @click="vibrate">震动</button>
      <button class="btn" @click="chooseImage">选图（相册）</button>
    </view>
  </view>
</template>

<script setup>
import { ref } from 'vue'
import { onShow } from '@dcloudio/uni-app'
import { probeShow } from '../../utils/probe.js'

const log = ref('ready')

onShow(() => probeShow('native'))

function writeStorage() {
  const v = { t: Date.now(), tip: 'xop-demo' }
  uni.setStorageSync('XOP_DEMO_NATIVE', v)
  log.value = `wrote ${JSON.stringify(v)}`
  console.log('[XOP-DEMO] writeStorage', v)
}
function readStorage() {
  const v = uni.getStorageSync('XOP_DEMO_NATIVE')
  log.value = `read ${JSON.stringify(v)}`
  console.log('[XOP-DEMO] readStorage', v)
}
function vibrate() {
  uni.vibrateShort({
    success: () => {
      log.value = 'vibrate ok'
      console.log('[XOP-DEMO] vibrate ok')
    },
    fail: (e) => {
      log.value = `vibrate fail ${e.errMsg || e}`
      console.warn('[XOP-DEMO] vibrate fail', e)
    }
  })
}
function chooseImage() {
  uni.chooseImage({
    count: 1,
    sizeType: ['compressed'],
    sourceType: ['album'],
    success: (res) => {
      log.value = `image ${res.tempFilePaths?.[0] || ''}`
      console.log('[XOP-DEMO] chooseImage ok', res.tempFilePaths)
    },
    fail: (e) => {
      log.value = `chooseImage fail ${e.errMsg || e}`
      console.warn('[XOP-DEMO] chooseImage fail', e)
    }
  })
}
</script>

<style scoped>
.page { padding-bottom: 40rpx; }
.card { margin: 24rpx; padding: 28rpx; background: #fff; border-radius: 16rpx; }
.title { font-size: 34rpx; font-weight: 700; margin-bottom: 16rpx; display: block; }
.mono { display: block; font-family: monospace; font-size: 24rpx; color: #333; margin-bottom: 16rpx; word-break: break-all; }
.btn { margin-top: 16rpx; }
</style>
