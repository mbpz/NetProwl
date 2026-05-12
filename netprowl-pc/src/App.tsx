import { useState } from 'react'
import { Home } from './pages/Home'
import { Devices } from './pages/Devices'
import { Topology } from './pages/Topology'
import './index.css'

type Tab = 'home' | 'devices' | 'topology'

function App() {
  const [tab, setTab] = useState<Tab>('home')

  return (
    <div className="app">
      <nav>
        <button onClick={() => setTab('home')}>首页</button>
        <button onClick={() => setTab('devices')}>设备</button>
        <button onClick={() => setTab('topology')}>拓扑</button>
      </nav>
      <main>
        {tab === 'home' && <Home />}
        {tab === 'devices' && <Devices />}
        {tab === 'topology' && <Topology />}
      </main>
    </div>
  )
}

export default App