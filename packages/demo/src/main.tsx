import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import "./index.css"
import App from "./App.js"

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)

const target =
  document.location.hostname === "localhost"
    ? "http://localhost:3001"
    : "https://ra-https.up.railway.app"

// Register Service Worker for all same-origin fetch requests
if ("serviceWorker" in navigator) {
  const swUrl = `/sw.js?target=${encodeURIComponent(target)}`
  navigator.serviceWorker
    .register(swUrl, { type: "module", scope: "/" })
    .catch((err) => {
      console.error("[ra-https] Could not register ServiceWorker", err)
      console.log(err.stack)
    })
} else {
  console.error("[ra-https] Could not find ServiceWorker API on this platform")
}
