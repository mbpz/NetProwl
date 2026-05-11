const OUI_MAP: Record<string, string> = {
  '00:50:56': 'VMware',
  '00:0c:29': 'VMware',
  'b8:27:eb': 'Raspberry Pi',
  'dc:a6:32': 'Raspberry Pi',
  'e4:5f:01': 'Raspberry Pi',
  '00:1e:68': 'Quanta (华为/H3C)',
  '00:25:9e': 'Cisco',
  '00:1a:2b': 'Cisco',
  '00:17:88': 'Philips Hue',
  'a8:66:7f': 'Apple',
  'f0:18:98': 'Apple',
  '3c:06:30': 'Apple',
  '00:e0:4c': 'Realtek',
  '00:23:cd': 'Intel',
  '00:1b:21': 'Intel',
  '00:0d:2b': 'Dell',
  '00:1c:23': 'Dell',
  '00:24:e8': 'Dell',
  '00:50:ba': 'Dell',
  'ac:de:48': 'Hangzhou Hikvision',
  'b4:15:13': 'Hangzhou Hikvision',
  '00:03:93': 'Siemens',
  '00:1b:a2': 'Schneider Electric',
}

/** Look up vendor by MAC OUI prefix */
export function lookupVendor(mac: string): string | null {
  const prefix = normalizeMac(mac).substring(0, 8)
  return OUI_MAP[prefix] || null
}

function normalizeMac(mac: string): string {
  return mac.replace(/[-:]/g, ':').toLowerCase()
}