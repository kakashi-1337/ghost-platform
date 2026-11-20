// libFuzzer harness for Nmap's FULL version-detection match pipeline.
// Constructs real ServiceProbeMatch objects (via InitMatch with genuine
// probe-file match lines), then drives testMatch() with hostile banners —
// exercising PCRE2 matching, ovector handling, getVersionStr, dotmplsubst,
// and every substvar handler ($1, $P, $SUBST, $I, cpe).
//
// The probe set intentionally requires trailing markers (ZZ) after capture
// groups so the KNOWN memcmp OOB READ (service_scan.cc:813, reached when
// a group ends at the buffer end) does NOT fire — this harness hunts for
// NEW bugs, especially OOB WRITES in the template machinery.
#include "service_scan.cc"

#include <cstdio>
#include <cstdlib>

// Global options object (normally in nmap.cc) — provided by NmapOps.o link
// (declared extern here to avoid duplicate definition)
extern NmapOps o;

static ServiceProbeMatch *probes[4] = {NULL, NULL, NULL, NULL};
static bool initialized = false;

static void init_probes() {
  if (initialized) return;
  initialized = true;
  // Real probe-file syntax; groups are followed by required "ZZ" so they
  // end >= findstrlen-1 bytes before the buffer end (avoids the known READ).
  static const char *lines[] = {
    "match fuzz1 m|^FUZZ1(.*?)TAILTAILTAILTAIL|s p/Fuzz One/ v/$1/ i/data $1/ ",
    "match fuzz2 m|^FUZZ2(.*?)TAILTAILTAILTAIL|s p/Fuzz Two/ v/$SUBST(1,\"QQQQQ\",\"Y\")/ i/sub $1/ ",
    "match fuzz3 m|^FUZZ3(.*?)TAILTAILTAILTAIL|s p/Fuzz Three/ v/$P(1)/ i/int $I(1,'>')/ ",
    "match fuzz4 m|^FUZZ4(.*?)TAILTAILTAILTAIL|s p/Fuzz Four/ v/$1/ h/$1/ o/$1/ d/$1/ cpe:/a:ven:p:$1/ ",
  };
  for (int i = 0; i < 4; i++) {
    probes[i] = new ServiceProbeMatch();
    probes[i]->InitMatch(lines[i], 100 + i);
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  init_probes();
  if (size < 8) return 0;

  // Run the FULL match pipeline on the hostile banner for every probe type.
  for (int i = 0; i < 4; i++) {
    const struct MatchDetails *md = probes[i]->testMatch((const u8 *) data, (int) size);
    (void) md;  // product/version strings already written internally
  }

  // Second pass with the banner reversed (different ovector geometries)
  u8 *rev = (u8 *) malloc(size);
  for (size_t i = 0; i < size; i++) rev[i] = data[size - 1 - i];
  for (int i = 0; i < 4; i++) {
    probes[i]->testMatch(rev, (int) size);
  }
  free(rev);

  return 0;
}
