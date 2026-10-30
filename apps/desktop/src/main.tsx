import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import '@fontsource/ibm-plex-sans/latin-400.css'
import '@fontsource/ibm-plex-sans/latin-500.css'
import '@fontsource/ibm-plex-sans/latin-600.css'
import '@fontsource/ibm-plex-mono/latin-400.css'
import '@fontsource/ibm-plex-mono/latin-500.css'
import './styles/tokens.css'
import './styles/global.css'
import './styles/navigation.css'
import './styles/shell.css'
import './styles/responsive.css'
import './styles/swarm.css'
import './styles/workspaces.css'
import App from './App'

const root = document.getElementById('root')

if (!root) {
  throw new Error('Application root element was not found')
}

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
