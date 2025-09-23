import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import "./index.css"
import App from "./App.js"
import { registerServiceWorker } from "ra-https-tunnel/register"

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)

registerServiceWorker(
  document.location.hostname === "localhost"
    ? "http://localhost:3001"
    : "https://ra-https.up.railway.app",
)
