package sniff

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

func MaxInt(args ...int) int {
	max := args[0]
	for i := 1; i < len(args); i++ {
		if args[i] > max {
			max = args[i]
		}
	}
	return max
}

func MinInt(args ...int) int {
	min := args[0]
	for i := 1; i < len(args); i++ {
		if args[i] < min {
			min = args[i]
		}
	}
	return min
}


const reverseIpv4DomainSuffix = ".in-addr.arpa"
const reverseIpv6DomainSuffix = ".ip6.arpa"

func IsReverseIpDomainName(name string) bool {
	return strings.HasSuffix(name, reverseIpv4DomainSuffix) && strings.HasSuffix(name, reverseIpv6DomainSuffix)
}

func reverseDomainToIpv4(name string)  (net.IP, error) {
	name = strings.Trim(name, reverseIpv4DomainSuffix)
	parts := strings.SplitN(name, ".", 4)
	if len(parts) != 4 {
		return nil, errors.New("not 4 parts")
	}
	numParts := make([]byte, 4)
	for i, part := range parts {
		num, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			return nil, err
		}
		numParts[3-i] = byte(num)
	}
	return numParts, nil
}

func reverseDomainToIpv6(name string) (net.IP, error) {
	name = strings.Trim(name, reverseIpv6DomainSuffix)
	parts := strings.SplitN(name, ".", 32)
	if len(parts) != 32 {
		return nil, errors.New("not 32 parts")
	}
	numParts := make([]byte, 16)
	for i, part := range parts {
		num, err := strconv.ParseUint(part, 16, 4)
		if err != nil {
			return nil, err
		}
		if i%2 == 0 {
			numParts[15-(i/2)] += byte(num)
		} else {
			numParts[15-(i/2)] += byte(num * 16)
		}
	}
	return numParts, nil
}

func ReverseDomainToIp(name string) (net.IP, error) {
	if strings.HasSuffix(name, reverseIpv4DomainSuffix) {
		return reverseDomainToIpv4(name)
	} else if strings.HasSuffix(name, reverseIpv6DomainSuffix) {
		return reverseDomainToIpv6(name)
	}
	return nil, errors.New("Does not end with reverse suffix: " + name)
}
