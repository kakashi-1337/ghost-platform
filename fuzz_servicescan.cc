// libFuzzer harness for Nmap's service version-detection response parsing:
// ServiceNFO::appendtocurrentproberesponse + addToServiceFingerprint +
// the regex-match/template-substitution pipeline on hostile banners.
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "nbase.h"
#include "NmapOps.h"
#include "service_scan.h"

// Global options object (normally defined in nmap.cc)
NmapOps o;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // 1) Accumulate the hostile banner as probe responses
  ServiceNFO svc(NULL);
  // feed in two chunks to exercise realloc growth paths
  size_t half = size / 2;
  svc.appendtocurrentproberesponse((const u8 *) data, (int) half);
  svc.appendtocurrentproberesponse((const u8 *) (data + half), (int) (size - half));

  // 2) Build the service fingerprint (escaping pipeline) from the response
  if (size > 0) {
    svc.addToServiceFingerprint("NULL", (const u8 *) data, (int) size);
  }

  // 3) Retrieve + fingerprint output
  int flen = 0;
  const char *fp = svc.getServiceFingerprint(&flen);
  (void) fp;
  (void) flen;

  return 0;
}
