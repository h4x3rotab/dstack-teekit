export function registerServiceWorker(target: string) {
  if ("serviceWorker" in navigator) {
    const swUrl = `/__ra-serviceworker__.js?target=${encodeURIComponent(
      target,
    )}`
    navigator.serviceWorker
      .register(swUrl, { type: "module", scope: "/" })
      .catch((err) => {
        console.error("[teekit] Could not register ServiceWorker", err)
        console.log(err.stack)
      })
  } else {
    console.error("[teekit] Could not find ServiceWorker API on this platform")
  }
}
