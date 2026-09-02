<template>
  <view class="page">
    <view class="card">
      <text class="title">XopProtector UniMP 探针</text>
      <text class="mono">{{ probeText }}</text>
    </view>

    <view class="card">
      <image
        class="hero"
        mode="aspectFill"
        src="https://picsum.photos/800/400"
        @error="onImgError"
        @load="onImgLoad"
      />
      <text class="hint">网络图（imagepipeline / Weex）: {{ imgStatus }}</text>
    </view>

    <view class="card">
      <button class="btn" type="primary" @click="goShop">进入分包详情</button>
      <button class="btn" @click="bump">本地计数 +1 (storage={{ count }})</button>
    </view>
  </view>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { onShow } from '@dcloudio/uni-app'
import { probeShow } from '../../utils/probe.js'

const imgStatus = ref('pending')
const count = ref(0)
const launch = ref(null)
const sys = ref({})

onShow(() => {
  probeShow('home')
})

onMounted(() => {
  try {
    launch.value = uni.getStorageSync('XOP_DEMO_LAUNCH') || null
    count.value = Number(uni.getStorageSync('XOP_DEMO_COUNT') || 0)
  } catch (e) {
    console.warn('[XOP-DEMO] storage read failed', e)
  }
  sys.value = uni.getSystemInfoSync()
  console.log('[XOP-DEMO] home mounted', JSON.stringify(sys.value))
})

const probeText = computed(() => {
  const l = launch.value || {}
  const s = sys.value || {}
  return [
    `launch.time=${l.time || '-'}`,
    `platform=${s.platform || '-'} / ${s.system || '-'}`,
    `window=${s.windowWidth}x${s.windowHeight}`,
    `uniPlatform=${s.uniPlatform || '-'}`,
    `若本页有内容且主题页能改 Tab 色 → JS 正常`,
    `若仅底部 Tab 可见、此处全白 → Weex/JS 失败`
  ].join('\n')
})

function onImgLoad() {
  imgStatus.value = 'ok'
  console.log('[XOP-DEMO] network image load ok')
}
function onImgError(e) {
  imgStatus.value = 'error'
  console.warn('[XOP-DEMO] network image error', e)
}
function bump() {
  count.value += 1
  uni.setStorageSync('XOP_DEMO_COUNT', count.value)
  console.log('[XOP-DEMO] count=', count.value)
}
function goShop() {
  uni.navigateTo({ url: '/subPackages/shop/detail/index?id=42' })
}
</script>

<style scoped>
.page { padding-bottom: 40rpx; }
.title { display: block; font-size: 36rpx; font-weight: 700; margin-bottom: 16rpx; }
.hero { width: 100%; height: 280rpx; border-radius: 12rpx; background: #e0e0e0; }
.hint { display: block; margin-top: 12rpx; color: #666; font-size: 24rpx; }
.card { margin: 24rpx; padding: 28rpx; background: #fff; border-radius: 16rpx; }
.btn { margin-top: 20rpx; }
.mono { font-family: monospace; font-size: 24rpx; line-height: 1.55; white-space: pre-wrap; color: #222; }
</style>
