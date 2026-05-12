import { useScanner } from '../hooks/useScanner'

export function Home() {
  const { startScan, scanning } = useScanner()

  return (
    <div className="home">
      <h2>网络扫描</h2>
      <button onClick={startScan} disabled={scanning}>
        {scanning ? '扫描中...' : '开始扫描'}
      </button>
    </div>
  )
}