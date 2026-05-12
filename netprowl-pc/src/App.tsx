import { useState } from 'react'

function App() {
  const [scanState, setScanState] = useState<'idle' | 'scanning' | 'done'>('idle')

  return (
    <div className="app">
      <header>
        <h1>NetProwl</h1>
      </header>
      <main>
        <button onClick={() => setScanState('scanning')}>
          {scanState === 'scanning' ? '扫描中...' : '开始扫描'}
        </button>
      </main>
    </div>
  )
}

export default App
