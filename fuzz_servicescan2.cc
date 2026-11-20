// libFuzzer harness for Nmap's service version-detection banner pipeline.
// Includes service_scan.cc directly so the internal ServiceNFO class becomes
// instantiable: appendtocurrentproberesponse (banner accumulation with the
// 4096 exact-allocation branch) + addToServiceFingerprint (escaping
// pipeline) + getServiceFingerprint.
#include "service_scan.cc"

#include <cstdio>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4) return 0;

  ServiceNFO svc(NULL);

  // Split into two chunks to exercise realloc growth + exact-allocation branch
  size_t half = size / 2;
  svc.appendtocurrentproberesponse((const u8 *) data, (int) half);
  svc.appendtocurrentproberesponse((const u8 *) (data + half), (int) (size - half));

  // Feed the full hostile buffer through fingerprint escaping
  svc.addToServiceFingerprint("NULL", (const u8 *) data, (int) size);

  int flen = 0;
  const char *fp = svc.getServiceFingerprint(&flen);
  (void) fp;
  (void) flen;

  return 0;
}
