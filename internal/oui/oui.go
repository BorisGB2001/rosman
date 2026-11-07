// Package oui maps a MAC-address prefix (OUI) to a vendor name. This is a
// curated subset of the public IEEE OUI registry (facts, not vendor assets);
// extend the map as needed. Unknown prefixes return "".
package oui

import "strings"

var m = map[string]string{
	// MikroTik / Routerboard
	"000C42": "MikroTik", "4C5E0C": "MikroTik", "488F5A": "MikroTik", "64D154": "MikroTik",
	"6C3B6B": "MikroTik", "744D28": "MikroTik", "CC2DE0": "MikroTik", "DC2C6E": "MikroTik",
	"E48D8C": "MikroTik", "085531": "MikroTik", "18FD74": "MikroTik", "2CC81B": "MikroTik",
	"789A18": "MikroTik", "B869F4": "MikroTik", "D4CA6D": "MikroTik", "F41E57": "MikroTik",
	"68FF7B": "MikroTik", "C4AD34": "MikroTik", "7483C2": "MikroTik", "D0E6BF": "MikroTik",
	// Apple
	"001451": "Apple", "0017F2": "Apple", "3C0754": "Apple", "A4B197": "Apple",
	"F0DBF8": "Apple", "DC2B2A": "Apple", "8866A5": "Apple", "A85C2C": "Apple",
	"04D3CF": "Apple", "9C207B": "Apple", "F0989D": "Apple", "BCD074": "Apple",
	// Samsung
	"001632": "Samsung", "0023D7": "Samsung", "5001BB": "Samsung", "8CF5A3": "Samsung",
	"C44202": "Samsung", "E8508B": "Samsung", "F008F1": "Samsung", "BC7210": "Samsung",
	// Intel
	"001B21": "Intel", "3C970E": "Intel", "7CB27D": "Intel", "A0A8CD": "Intel",
	"E4A471": "Intel", "9440C9": "Intel", "0C8BFD": "Intel", "34415D": "Intel",
	// Espressif (ESP IoT)
	"240AC4": "Espressif", "3C6105": "Espressif", "8CAAB5": "Espressif", "A4CF12": "Espressif",
	"B4E62D": "Espressif", "ECFABC": "Espressif", "7CDFA1": "Espressif",
	// TP-Link
	"6466B3": "TP-Link", "50C7BF": "TP-Link", "A42BB0": "TP-Link", "003192": "TP-Link",
	"B0487A": "TP-Link", "C006C3": "TP-Link",
	// Ubiquiti
	"0418D6": "Ubiquiti", "24A43C": "Ubiquiti", "68D79A": "Ubiquiti", "802AA8": "Ubiquiti",
	"B4FBE4": "Ubiquiti", "FCECDA": "Ubiquiti", "74ACB9": "Ubiquiti", "788A20": "Ubiquiti",
	// Huawei / Honor
	"001E10": "Huawei", "48435A": "Huawei", "70723C": "Huawei", "AC853D": "Huawei",
	"D0D04B": "Huawei", "F83DFF": "Huawei",
	// Xiaomi
	"286C07": "Xiaomi", "640980": "Xiaomi", "7802F8": "Xiaomi", "A0860C": "Xiaomi",
	"F0B429": "Xiaomi", "FC64BA": "Xiaomi",
	// Others
	"001A11": "Google", "F4F5E8": "Google", "3C5AB4": "Google",
	"FCA183": "Amazon", "44650D": "Amazon", "68543D": "Amazon",
	"000D93": "Apple", "001124": "Apple",
	"D8EB97": "TRENDnet", "001AA0": "Dell", "B083FE": "Dell", "F8BC12": "Dell",
	"3C D9 2B": "HP", "A45D36": "HP", "001B78": "HP",
	"00005E": "IANA", "FCFBFB": "Cisco", "00000C": "Cisco", "001121": "Cisco",
	"52540": "QEMU/KVM", "525400": "QEMU/KVM", "080027": "VirtualBox",
	"000569": "VMware", "005056": "VMware", "001C14": "VMware",
	"0050F2": "Microsoft", "0017FA": "Microsoft",
	"001D0F": "Realtek", "52544C": "Realtek", "001E8C": "ASUSTek", "2C56DC": "ASUSTek",
	"A0F3C1": "TP-Link", "C46E1F": "TP-Link", "000FB5": "Netgear", "20E52A": "Netgear",
	"0022B0": "D-Link", "14D64D": "D-Link", "001349": "Zyxel", "B0B2DC": "Zyxel",
}

// Vendor returns the vendor for a MAC address, or "" if unknown.
func Vendor(mac string) string {
	var p strings.Builder
	for _, r := range mac {
		if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'F') {
			p.WriteRune(r)
		} else if r >= 'a' && r <= 'f' {
			p.WriteRune(r - 32)
		}
		if p.Len() == 6 {
			break
		}
	}
	return m[p.String()]
}
