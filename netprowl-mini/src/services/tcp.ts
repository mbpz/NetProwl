const WHITE_PORTS = [80, 443, 8080, 8443, 554, 5000, 9000, 49152]
const CONCURRENCY = 20
const TIMEOUT_MS = 2000

export async function probeTCPPorts(ip: string): Promise<number[]> {
  const open: number[] = []
  const chunks = chunkArray(WHITE_PORTS, CONCURRENCY)

  for (const group of chunks) {
    const results = await Promise.all(group.map(port => probePort(ip, port)))
    results.forEach((p, i) => { if (p) open.push(group[i]) })
    await delay(50)
  }
  return open
}

async function probePort(ip: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = wx.createTCPSocket()
    let settled = false
    const timer = setTimeout(() => {
      if (!settled) { settled = true; socket.close(); resolve(false) }
    }, TIMEOUT_MS)

    socket.onConnect(() => {
      if (!settled) { settled = true; clearTimeout(timer); socket.close(); resolve(true) }
    })
    socket.onError(() => {
      if (!settled) { settled = true; clearTimeout(timer); socket.close(); resolve(false) }
    })
    socket.connect({ address: ip, port })
  })
}

function chunkArray<T>(arr: T[], size: number): T[][] {
  const out: T[][] = []
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size))
  return out
}

function delay(ms: number) {
  return new Promise(r => setTimeout(r, ms))
}
