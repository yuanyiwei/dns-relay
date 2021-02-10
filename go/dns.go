package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type dnsHeader struct {
	id        []byte
	questions int64 // 0 query，1 answer
	opcode    int64
	aa        int64 //authoritative answer
	tc        int64 //truncated
	rd        int64 //Recursion Desired
	ra        int64 //Recursion Available
	z         int64
	retcode   int64 //0 : OK;1 : Format error;2 : Server failure;3 : Name Error;4 : Not Implemented;5 : Refused
	qdcount   int64
	ancount   int64
	nscount   int64
	arcount   int64
}

type dnsQuestion struct {
	qname  []byte
	qtype  []byte
	qclass []byte
}

type dnsAnswer struct {
	aname  []byte
	atype  []byte
	aclass []byte
	ttl    int64
	rdlen  int64
	rdata  []byte
}

type dnsPkg struct {
	header   dnsHeader
	question dnsQuestion
	answer   dnsAnswer
}

var dnsQtype = map[int64]string{
	1: "A",
	2: "NS",
	// 3:   "MD",
	// 4:   "MF",
	5: "CNAME",
	6: "SOA",
	// 7:   "MB",
	// 8:   "MG",
	// 9:   "MR",
	// 10:  "NULL",
	11:  "WKS",
	12:  "PTR",
	13:  "HINFO",
	14:  "MINFO",
	15:  "MX",
	16:  "TXT",
	28:  "AAAA",
	252: "AXFR",
	255: "ANY",
}

// some qtype out of date

func getHeader(data []byte) dnsHeader {
	flags := data[2:4]
	flagsStr := BytesToBin(flags)

	header := &dnsHeader{
		id:        data[0:2],
		questions: string2i64(flagsStr[1:2]),
		opcode:    string2i64(flagsStr[2:6]),
		aa:        string2i64(flagsStr[6:7]),
		tc:        string2i64(flagsStr[7:8]),
		rd:        string2i64(flagsStr[8:9]),
		ra:        string2i64(flagsStr[10:11]),
		z:         string2i64(flagsStr[11:14]),
		retcode:   string2i64(flagsStr[14:18]),
		qdcount:   bytes2i64(data[4:6]),
		ancount:   bytes2i64(data[6:8]),
		nscount:   bytes2i64(data[8:10]),
		arcount:   bytes2i64(data[10:12]),
	}
	return *header
}

// TODO getAnswer

func getQuestion(data []byte) dnsQuestion {
	datalen := len(data)
	qnameBytes := data[12 : datalen-4]
	question := &dnsQuestion{
		qname:  qnameBytes,
		qtype:  data[datalen-4 : datalen-2],
		qclass: data[datalen-2 : datalen],
	}
	return *question
}

/*
func ListenUDP(network string, laddr *UDPAddr) (*UDPConn, error) {
    switch network {
    case "udp", "udp4", "udp6":
    default:
        return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: laddr.opAddr(), Err: UnknownNetworkError(network)}
    }
    if laddr == nil {
        laddr = &UDPAddr{}
    }
    sl := &sysListener{network: network, address: laddr.String()}
    c, err := sl.listenUDP(context.Background(), laddr)
    if err != nil {
        return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: laddr.opAddr(), Err: err}
    }
    return c, nil
}

func DialUDP(network string, laddr, raddr *UDPAddr) (*UDPConn, error) {
    switch network {
    case "udp", "udp4", "udp6":
    default:
        return nil, &OpError{Op: "dial", Net: network, Source: laddr.opAddr(), Addr: raddr.opAddr(), Err: UnknownNetworkError(network)}
    }
    if raddr == nil {
        return nil, &OpError{Op: "dial", Net: network, Source: laddr.opAddr(), Addr: nil, Err: errMissingAddress}
    }
    sd := &sysDialer{network: network, address: raddr.String()}
    c, err := sd.dialUDP(context.Background(), laddr, raddr)
    if err != nil {
        return nil, &OpError{Op: "dial", Net: network, Source: laddr.opAddr(), Addr: raddr.opAddr(), Err: err}
    }
    return c, nil
}
*/

func forward2upstream(data []byte, remoteDns string) []byte {
	socket, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP(remoteDns),
		Port: 53,
	})
	if err != nil {
		log.Println("Error Dns server", err)
		return nil
	}
	t := time.Now()

	_ = socket.SetDeadline(t.Add(2 * time.Second))
	defer socket.Close()

	_, err = socket.Write(data)
	if err != nil {
		log.Println("Error Write query,", err)
		return nil
	}
	revdata := make([]byte, 512)
	rn, remoteAddr, err := socket.ReadFromUDP(revdata)
	if err != nil {
		log.Println("Error Read From remoteDns,", err)
		return nil
	}
	log.Println("forward query to", remoteAddr)
	// fmt.Println(revdata[:rn])
	// fmt.Println(getHeader(revdata[:rn]))
	// fmt.Println(getQuestion(revdata[:rn]))
	// log.Printf("%x\n", revdata[:rn])
	log.Println(
		"Cost time:",
		time.Since(t),
	)
	return revdata[:rn]
}

func readConfig(configPath string) map[string]string {
	ipRe := regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	domainRe := regexp.MustCompile(`([a-z0-9--]{1,200})\.([a-z]{2,10})(\.[a-z]{2,10})?`)

	var hosts = map[string]string{}
	f, _ := os.OpenFile(configPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	defer f.Close()
	ListScanner := bufio.NewScanner(f)
	for ListScanner.Scan() {
		var ip, name string
		itemList := ListScanner.Text()
		if string([]byte(itemList)[:1]) == "#" || itemList == "" {
			continue
		}
		itemList = strings.Split(itemList, "#")[0]

		item := strings.Split(itemList, " ")
		if len(item) > 1 {
			for _, itemStr := range item {
				if ipRe.MatchString(itemStr) {
					ip = itemStr
				} else if domainRe.MatchString(itemStr) {
					name = itemStr
				}
				if ip != "" && name != "" {
					hosts[name] = ip
				}
				name = ""
			}
		}
	}
	return hosts
}

func hook(header dnsHeader, question dnsQuestion, ip string) []byte {

	response := dnsPkg{}

	response.header.id = header.id
	response.header.questions = 1
	response.header.opcode = 0
	response.header.aa = 0
	response.header.tc = 0
	response.header.rd = 1
	response.header.ra = 0
	response.header.z = 0
	response.header.retcode = 0
	response.header.qdcount = 1
	response.header.ancount = 1
	response.header.nscount = 0
	response.header.arcount = 0

	response.question = question

	response.answer.aname = question.qname
	response.answer.atype = question.qtype
	response.answer.aclass = question.qclass
	response.answer.ttl = 600
	response.answer.rdlen = 4
	response.answer.rdata = ipAddrToByte(ip)

	return dnsResponse2bytes(response)
}

func dnsResponse2bytes(response dnsPkg) []byte {
	// TODO
	// var buf = new(bytes.Buffer)
	// err := binary.Write(buf, binary.BigEndian, &response.header.id)
	buf := make([]byte, 32+len(response.question.qname))
	offset := len(response.question.qname)
	writebytesToBuffer(buf, response.header.id, 0)

	buf[2] = byte(0x00 | response.header.questions<<7 | response.header.opcode<<3 | response.header.aa<<2 | response.header.tc<<1 | response.header.rd)
	buf[3] = byte(0x00 | response.header.ra<<7 | response.header.z<<4 | response.header.retcode)
	buf[4] = byte(0x00)
	buf[5] = byte(0x00 | response.header.qdcount)
	buf[6] = byte(0x00)
	buf[7] = byte(0x00 | response.header.ancount)
	writebytesToBuffer(buf, []byte{0x00, 0x00, 0x00, 0x00}, 8)

	writebytesToBuffer(buf, response.question.qname, 12)
	writebytesToBuffer(buf, response.question.qtype, int64(offset)+12)
	writebytesToBuffer(buf, response.question.qclass, int64(offset)+14)
	writebytesToBuffer(buf, []byte{0xc0, 0x0c}, int64(offset)+16)
	writebytesToBuffer(buf, response.answer.atype, int64(offset)+18)
	writebytesToBuffer(buf, response.answer.aclass, int64(offset)+20)
	writebytesToBuffer(buf, []byte{0x00, 0x00}, int64(offset)+22)
	writebytesToBuffer(buf, i642bytes(response.answer.ttl), int64(offset)+24)
	writebytesToBuffer(buf, i642bytes(response.answer.rdlen), int64(offset)+26)
	writebytesToBuffer(buf, response.answer.rdata, int64(offset)+28)

	return buf
}

func ipAddrToByte(ipAddr string) []byte {
	bits := strings.Split(ipAddr, ".")
	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])
	return []byte{byte(b0), byte(b1), byte(b2), byte(b3)}
}

func parseDomain(buf []byte) string {
	items := make([]string, 0)
	for i := 0; i < len(buf); {
		bufflen := int(buf[i])
		if bufflen == 0 {
			break
		}
		offset := i + 1
		items = append(items, string(buf[offset:offset+bufflen]))
		i = offset + bufflen
	}
	return strings.Join(items, ".")
}

func writebytesToBuffer(buffer []byte, buf []byte, n int64) []byte {
	for _, b := range buf {
		buffer[n] = b
		n++
	}
	return buffer
}

func i642bytes(i int64) []byte {
	bBuf := bytes.NewBuffer([]byte{})
	_ = binary.Write(bBuf, binary.BigEndian, i)
	return bBuf.Bytes()[len(bBuf.Bytes())-2:]
}

func bytes2i64(buf []byte) int64 {
	bufStr := BytesToBin(buf)
	bufint64, _ := strconv.ParseInt(bufStr[len(bufStr)-5:len(bufStr)-1], 10, 64)
	return bufint64
}

func string2i64(str string) int64 {
	intStr, _ := strconv.ParseInt(str, 10, 64)
	return intStr
}

func BytesToBin(bs []byte) string {
	buf := make([]byte, 0, len(bs)*9+1)
	buf = append(buf, byte('['))
	for _, b := range bs {
		buf = appendBin(buf, b)
		buf = append(buf, byte(' '))
	}
	buf[len(bs)*9] = byte(']')
	return string(buf)
}

func appendBin(bs []byte, b byte) []byte {
	for i := 0; i < 8; i++ {
		a := b
		b <<= 1
		b >>= 1
		switch a {
		case b:
			bs = append(bs, byte('0'))
		default:
			bs = append(bs, byte('1'))
		}
		b <<= 1
	}
	return bs
}

func main() {
	remoteDns := "223.5.5.5"
	configPath := "./config"

	// hosts
	dnsMap := readConfig(configPath)
	if len(dnsMap) != 0 {
		log.Println("Valid config:")
		for dnsName, dnsIp := range dnsMap {
			fmt.Println(dnsIp, dnsName)
		}
		fmt.Println()
	} else {
		dnsMap = nil
		fmt.Println("No config detected, working in dns relay mode")
		fmt.Println("Please Add config file in ./config")
	}

	// udp 53 serve
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 53})
	if err != nil {
		log.Println(err)
		return
	}
	defer srv.Close()

	log.Println("Server started, Listening at " + srv.LocalAddr().String())

	data := make([]byte, 1024)

	for {
		n, remoteAddr, ReadFromQueryErr := srv.ReadFromUDP(data)

		header := getHeader(data[:n])
		question := getQuestion(data[:n])

		if ReadFromQueryErr != nil {
			log.Printf("error during read: %s", ReadFromQueryErr)
		}
		//log.Println(dnsMap == nil)
		//log.Println(dnsMap[parseDomain(question.qname)] == "")

		if dnsMap == nil || dnsMap[parseDomain(question.qname)] == "" {
			// query
			log.Println("query", parseDomain(question.qname), "on", remoteDns)
			revdata := forward2upstream(data[:n], remoteDns)
			_, writeErr := srv.WriteToUDP(revdata, remoteAddr)

			if writeErr != nil {
				log.Printf("Error write %s", writeErr)
			}
			//log.Println("id", header.id)
			//log.Println("query questions", header.questions)
			//log.Println("answer questions", getHeader(revdata).questions)

		} else {
			// hook
			//log.Println(parseDomain(question.qname))
			//log.Println(dnsMap[parseDomain(question.qname)])
			rsp := hook(header, question, dnsMap[parseDomain(question.qname)])
			log.Println("hook", parseDomain(question.qname), "of", dnsMap[parseDomain(question.qname)])
			_, writeErr := srv.WriteToUDP(rsp, remoteAddr)
			if writeErr != nil {
				log.Printf("error during write: %s", writeErr)
			}
		}
	}
}
