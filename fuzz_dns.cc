// libFuzzer harness for Nmap's internal DNS response parser (massdns.cc).
// Drives DNS::Factory::parseDomainName (label decompression over hostile
// response bytes), parseUnsignedShort/Int, parseIPv4/6 with fuzz offsets.
#include "libnetutil/massdns.h"
#include "NmapOps.h"
#include "libnetutil/netutil.h"

#include <cstdio>
#include <cstring>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4) return 0;

  // Exercise the domain-name decompressor at several offsets, with hostile
  // compression pointers (0xC0-prefixed) and label lengths.
  std::string name;
  for (size_t off = 0; off < size && off < 64; off += 1 + (data[off] & 7)) {
    DNS::Factory::parseDomainName(name, data, off, size);
    if (!name.empty()) name.clear();
  }

  // Full-response style: treat bytes 2.. as counts and walk records
  if (size >= 12) {
    u16 num;
    u32 num32;
    struct in_addr a4;
    struct in6_addr a6;
    size_t off = 0;
    DNS::Factory::parseUnsignedShort(num, data, off, size);
    DNS::Factory::parseUnsignedInt(num32, data, off + 2, size);
    DNS::Factory::parseIPv4(a4, data, off + 4, size);
    DNS::Factory::parseIPv6(a6, data, off + 6, size);

    // Walk a chain of names across the whole hostile buffer
    size_t pos = 12 % size;
    for (int i = 0; i < 32; i++) {
      std::string n2;
      size_t consumed = DNS::Factory::parseDomainName(n2, data, pos, size);
      if (consumed == 0 || consumed > size) break;
      pos = (pos + consumed) % size;
    }
  }

  return 0;
}
