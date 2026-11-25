import {onUnmounted, ref} from 'vue'

/** Seconds since start(), ticking once a second, so a long wait never looks stuck.
 * start() returns a stop for that round only: an abandoned round that ends
 * after a newer start() leaves the newer counter running. */
export function useElapsed() {
 const seconds = ref(0)
 let timer: ReturnType<typeof setInterval> | undefined
 let began = 0
 let round = 0
 function stop() {
  if(timer) clearInterval(timer)
  timer = undefined
 }
 function start(): () => void {
  stop()
  const mine = ++round
  began = Date.now()
  seconds.value = 0
  timer = setInterval(() => {seconds.value = Math.floor((Date.now() - began) / 1000)}, 1000)
  return () => {if(round === mine) stop()}
 }
 onUnmounted(stop)
 return {seconds, start, stop}
}

/** After this many seconds a wait says that a busy NAS can take minutes. */
export const SLOW_AFTER = 20
