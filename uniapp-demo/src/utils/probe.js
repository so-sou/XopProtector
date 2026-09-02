/** Emit probe to console + host native logcat via UniMP bridge. */
export function probeShow(page) {
  const msg = `[XOP-DEMO] page-show:${page}`
  // eslint-disable-next-line no-console
  console.log(msg)
  try {
    // Host: UnimpDemoApp setOnUniMPEventCallBack → Log.i(unimp.XopDemo, ...)
    uni.sendNativeEvent(
      'xop-probe',
      { page, t: Date.now(), event: 'page-show' },
      () => {}
    )
  } catch (e) {
    // eslint-disable-next-line no-console
    console.warn('[XOP-DEMO] sendNativeEvent failed', e)
  }
}

export function probeLaunch(info) {
  // eslint-disable-next-line no-console
  console.log('[XOP-DEMO] onLaunch', JSON.stringify(info || {}))
  try {
    uni.sendNativeEvent(
      'xop-probe',
      { event: 'launch', t: Date.now(), ...(info || {}) },
      () => {}
    )
  } catch (e) {
    // eslint-disable-next-line no-console
    console.warn('[XOP-DEMO] sendNativeEvent launch failed', e)
  }
}
