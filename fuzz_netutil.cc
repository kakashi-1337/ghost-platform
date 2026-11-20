// libFuzzer harness for Nmap's hostile-packet parsers.
//
// Feeds fuzzed bytes into the libnetutil packet parser chain that OS
// detection uses on responses from scanned hosts:
//   PacketParser::parse_packet / split (Ethernet/IP/TCP/UDP/ICMP walking)
//   TCPOptions::fromTCPHeader / foreachOpt (hostile TCP options)
// plus FPEngine's FPResponse-style buffer copy.
//
// Build:
//   clang++ -g -O1 -fsanitize=fuzzer,address -I<nmap> -I<nmap>/nbase \
//     fuzz_netutil.cc <nmap>/libnetutil/*.o <nmap>/nbase/libnbase.a -lpthread -lssl -lcrypto

#include <cstdio>
#include <cstring>
#include <vector>

#include "nbase.h"
#include "PacketParser.h"
#include "TCPHeader.h"
#include "IPv4Header.h"
#include "UDPHeader.h"
#include "ICMPv4Header.h"
#include "EthernetHeader.h"
#include "ARPHeader.h"
#include "DestOptsHeader.h"
#include "FragmentHeader.h"
#include "HopByHopHeader.h"
#include "RoutingHeader.h"
#include "RawData.h"

static bool opt_cb(u8 op, u8 oplen, const u8 *data, void *ctx) {
  // mimic FPEngine's tcpopt_vectorize reads
  volatile unsigned sum = 0;
  if (op == 2 && oplen == 4 && data) {
    sum += (data[2] << 8) + data[3];
  }
  if (op == 3 && oplen == 3 && data) {
    sum += data[2];
  }
  if (op == 8 && oplen == 10 && data) {
    sum += data[0] | data[4];
  }
  return true;  // keep iterating all options
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // 1) Raw packet parse (Ethernet + everything above it)
  if (size >= 14) {
    PacketElement *pe = PacketParser::split((const u8 *) data, size, true);
    if (pe != NULL) {
      std::vector<PacketElement *> elems;
      PacketElement *cur = pe;
      int layers = 0;
      while (cur != NULL && layers < 64) {
        elems.push_back(cur);
        cur = cur->getNextElement();
        layers++;
      }
      for (PacketElement *e : elems) {
        delete e;
      }
    }
  }

  // 2) IP-start parse (no Ethernet)
  if (size >= 20) {
    PacketElement *pe = PacketParser::split((const u8 *) data, size, false);
    if (pe != NULL) {
      std::vector<PacketElement *> elems;
      PacketElement *cur = pe;
      int hops = 0;
      while (cur != NULL && hops < 32) {
        elems.push_back(cur);
        TCPHeader *tcp = dynamic_cast<TCPHeader *>(cur);
        if (tcp != NULL) {
          TCPOptions opts;
          if (opts.fromTCPHeader(*tcp)) {
            opts.foreachOpt(opt_cb, NULL);
          }
        }
        cur = cur->getNextElement();
        hops++;
      }
      for (PacketElement *e : elems) {
        delete e;
      }
    }
  }

  // 3) Direct TCPOptions::fromBuffer walk (options bytes only)
  if (size >= 1) {
    TCPOptions opts;
    if (opts.fromBuffer((const u8 *) data, (int) size)) {
      opts.foreachOpt(opt_cb, NULL);
    }
  }

  // 4) TCPOptions::fromTCPPacket (raw tcp packet)
  if (size >= 20) {
    TCPOptions opts;
    if (opts.fromTCPPacket((const u8 *) data, (int) size)) {
      opts.foreachOpt(opt_cb, NULL);
    }
  }

  return 0;
}
