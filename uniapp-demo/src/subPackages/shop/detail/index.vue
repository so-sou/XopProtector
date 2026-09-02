<template>
  <view class="page">
    <view class="card">
      <text class="title">分包商品详情 #{{ id }}</text>
      <swiper class="banner" circular autoplay interval="2500">
        <swiper-item v-for="(src, i) in banners" :key="i">
          <image class="banner-img" :src="src" mode="aspectFill" />
        </swiper-item>
      </swiper>
      <text class="desc">
        分包加载成功说明 DCloud 资源路径正常。若从首页跳转后白屏，对照 logcat 的 page-show:shop-detail。
      </text>
      <button type="primary" @click="back">返回</button>
    </view>
  </view>
</template>

<script setup>
import { ref } from 'vue'
import { onLoad, onShow } from '@dcloudio/uni-app'
import { probeShow } from '../../../utils/probe.js'

const id = ref('-')
const banners = [
  'https://picsum.photos/seed/xop1/800/400',
  'https://picsum.photos/seed/xop2/800/400',
  'https://picsum.photos/seed/xop3/800/400'
]

onLoad((q) => {
  id.value = (q && q.id) || '0'
  console.log('[XOP-DEMO] shop-detail onLoad id=', id.value)
})
onShow(() => probeShow('shop-detail'))

function back() {
  uni.navigateBack()
}
</script>

<style scoped>
.page { padding-bottom: 40rpx; }
.card { margin: 24rpx; padding: 28rpx; background: #fff; border-radius: 16rpx; }
.title { font-size: 34rpx; font-weight: 700; display: block; margin-bottom: 16rpx; }
.banner { height: 320rpx; border-radius: 12rpx; overflow: hidden; }
.banner-img { width: 100%; height: 320rpx; }
.desc { display: block; margin: 20rpx 0; color: #555; font-size: 26rpx; line-height: 1.5; }
</style>
