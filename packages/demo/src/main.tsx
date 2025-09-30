import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import "./index.css"
import App, { baseUrl } from "./App.js"
import { registerServiceWorker } from "tee-channels-tunnel/register"

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)

registerServiceWorker(baseUrl)
