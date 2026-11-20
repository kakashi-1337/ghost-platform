// libFuzzer harness: Nmap version detection with the REAL shipped
// nmap-service-probes file (11,969 regexes + all templates) against
// hostile banners — the exact configuration of a victim nmap user.
//
// Any crash here is remotely exploitable by a hostile scanned host
// (banner-only attacker control, shipped config on the scanner side).
#include "service_scan.cc"

#include <cstdio>
#include <cstdlib>
#include <vector>

extern NmapOps o;

static AllProbes *AP = NULL;
static std::vector<ServiceProbe *> probe_list;
static bool initialized = false;

static void init_all_probes() {
  if (initialized) return;
  initialized = true;
  AP = new AllProbes();
  parse_nmap_service_probe_file(AP,
    "/home/dave/deepseek-harness/default-workspace/nmap_experiment/nmap/nmap-service-probes");
  probe_list = AP->probes;
  // note: nullProbe handled separately
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  init_all_probes();
  if (size < 4) return 0;

  // The NULL probe sees connect-time banners first (most realistic path)
  if (AP->nullProbe != NULL) {
    AP->nullProbe->testMatch((const u8 *) data, (int) size, 0);
  }

  // Rotate through shipped probes chosen by input bytes: coverage-guided
  // exploration picks probes whose regexes/templates reveal new paths.
  size_t n = probe_list.size();
  if (n > 0) {
    unsigned idx = (data[0] << 8 | data[1]) % n;
    for (int k = 0; k < 4 && k < (int) n; k++) {
      probe_list[(idx + k) % n]->testMatch((const u8 *) data, (int) size, 0);
    }
  }

  return 0;
}
