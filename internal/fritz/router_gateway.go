package fritz

import (
	"net"
	"os/exec"
	"runtime"
	"strings"
)

// defaultGatewayFromRoute parses the routing table to find the default gateway.
func defaultGatewayFromRoute() (net.IP, error) {
	switch runtime.GOOS {
	case "darwin":
		return defaultGatewayDarwin()
	case "linux":
		return defaultGatewayLinux()
	case "windows":
		return defaultGatewayWindows()
	default:
		return nil, nil
	}
}

func defaultGatewayDarwin() (net.IP, error) {
	out, err := exec.Command("netstat", "-rn").Output()
	if err != nil {
		return nil, err
	}
	return parseDarwinDefaultGateway(string(out))
}

func parseDarwinDefaultGateway(output string) (net.IP, error) {
	lines := strings.Split(output, "\n")
	inDefaultSection := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "default") || strings.HasPrefix(line, "0.0.0.0") {
			inDefaultSection = true
		}
		if inDefaultSection && line != "" {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				gw := fields[1]
				if ip := net.ParseIP(gw); ip != nil {
					return ip, nil
				}
			}
		}
		if inDefaultSection && line == "" {
			inDefaultSection = false
		}
	}
	return nil, nil
}

func defaultGatewayLinux() (net.IP, error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return nil, err
	}
	return parseLinuxDefaultGateway(string(out))
}

func parseLinuxDefaultGateway(output string) (net.IP, error) {
	fields := strings.Fields(strings.TrimSpace(output))
	for i, field := range fields {
		if field == "via" && i+1 < len(fields) {
			if ip := net.ParseIP(fields[i+1]); ip != nil {
				return ip, nil
			}
		}
	}
	return nil, nil
}

func defaultGatewayWindows() (net.IP, error) {
	out, err := exec.Command("route", "print", "0.0.0.0").Output()
	if err != nil {
		return nil, err
	}
	return parseWindowsDefaultGateway(string(out))
}

func parseWindowsDefaultGateway(output string) (net.IP, error) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "0.0.0.0") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				gw := fields[2]
				if ip := net.ParseIP(gw); ip != nil {
					return ip, nil
				}
			}
		}
	}
	return nil, nil
}
