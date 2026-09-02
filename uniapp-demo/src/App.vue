<script>
import { probeLaunch } from './utils/probe.js'

export default {
  onLaunch() {
    const sys = uni.getSystemInfoSync()
    const info = {
      tag: 'XOP-DEMO',
      event: 'launch',
      time: Date.now(),
      platform: sys.platform,
      system: sys.system,
      uniPlatform: sys.uniPlatform,
      windowWidth: sys.windowWidth,
      windowHeight: sys.windowHeight
    }
    probeLaunch(info)
    try {
      uni.setStorageSync('XOP_DEMO_LAUNCH', info)
    } catch (e) {
      console.warn('[XOP-DEMO] setStorageSync failed', e)
    }
  },
  onShow() {
    console.log('[XOP-DEMO] App onShow')
  },
  onHide() {
    console.log('[XOP-DEMO] App onHide')
  }
}
</script>

<style>
page {
  background-color: #f5f6f8;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
}
.card {
  margin: 24rpx;
  padding: 28rpx;
  background: #fff;
  border-radius: 16rpx;
  box-shadow: 0 4rpx 16rpx rgba(0, 0, 0, 0.04);
}
.btn {
  margin-top: 20rpx;
  background: #1976d2;
  color: #fff;
  border-radius: 12rpx;
}
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 24rpx;
  line-height: 1.5;
  color: #333;
  word-break: break-all;
}
</style>
