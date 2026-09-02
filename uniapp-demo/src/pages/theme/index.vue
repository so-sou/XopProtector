<template>
  <view class="page" :style="{ backgroundColor: bg }">
    <view class="card">
      <text class="title">动态主题 / TabBar</text>
      <text class="sub">
        加固失败常见表现：底部 Tab 仍在，但内容区白屏、Tab 颜色无法切换。
      </text>
      <view class="swatch" :style="{ backgroundColor: accent }"></view>
      <button class="btn" type="primary" @click="applyTheme('blue')">蓝色主题</button>
      <button class="btn" type="warn" @click="applyTheme('orange')">橙色主题</button>
      <button class="btn" @click="applyTheme('green')">绿色主题</button>
      <text class="mono">current={{ theme }} accent={{ accent }}</text>
    </view>
  </view>
</template>

<script setup>
import { ref } from 'vue'
import { onShow } from '@dcloudio/uni-app'
import { probeShow } from '../../utils/probe.js'

const theme = ref('blue')
const accent = ref('#007AFF')
const bg = ref('#E3F2FD')

onShow(() => probeShow('theme'))

function applyTheme(name) {
  theme.value = name
  const map = {
    blue: { selected: '#007AFF', bg: '#E3F2FD', tabBg: '#FFFFFF' },
    orange: { selected: '#FF5722', bg: '#FFF3E0', tabBg: '#FFF8F0' },
    green: { selected: '#2E7D32', bg: '#E8F5E9', tabBg: '#F1F8F2' }
  }
  const t = map[name]
  accent.value = t.selected
  bg.value = t.bg
  uni.setTabBarStyle({
    color: '#7A7E83',
    selectedColor: t.selected,
    backgroundColor: t.tabBg,
    borderStyle: 'black'
  })
  console.log('[XOP-DEMO] setTabBarStyle', name, t.selected)
  uni.showToast({ title: `theme=${name}`, icon: 'none' })
}
</script>

<style scoped>
.page { min-height: 100vh; padding-bottom: 40rpx; }
.card { margin: 24rpx; padding: 28rpx; background: #fff; border-radius: 16rpx; }
.title { font-size: 34rpx; font-weight: 700; }
.sub { display: block; margin: 12rpx 0 20rpx; color: #555; font-size: 26rpx; line-height: 1.5; }
.swatch { height: 120rpx; border-radius: 12rpx; margin-bottom: 20rpx; }
.btn { margin-top: 16rpx; }
.mono { display: block; margin-top: 20rpx; font-family: monospace; font-size: 24rpx; color: #333; }
</style>
