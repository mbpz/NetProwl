package util

import "strings"

var OUI_MAP = map[string]string{
	"00:50:56": "VMware",
	"00:0c:29": "VMware",
	"b8:27:eb": "Raspberry Pi",
	"dc:a6:32": "Raspberry Pi",
	"e4:5f:01": "Raspberry Pi",
	"00:1e:68": "Huawei/H3C",
	"00:25:9e": "Cisco",
	"00:1a:2b": "Cisco",
	"00:17:88": "Philips Hue",
	"a8:66:7f": "Apple",
	"f0:18:98": "Apple",
	"3c:06:30": "Apple",
	"00:e0:4c": "Realtek",
	"00:23:cd": "Intel",
	"00:1b:21": "Intel",
	"00:0d:2b": "Dell",
	"00:1c:23": "Dell",
	"00:24:e8": "Dell",
	"ac:de:48": "Hikvision",
	"b4:15:13": "Hikvision",
}

func LookupVendor(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	prefix := strings.ToLower(strings.ReplaceAll(mac[:8], "-", ":"))
	return OUI_MAP[prefix]
}