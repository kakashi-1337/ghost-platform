// libFuzzer harness for FPEngine's OS-fingerprint response vectorizer.
// Includes FPEngine.cc directly so the file-static vectorize() becomes
// callable, then feeds hostile FPResponse buffers (probe replies from the
// scanned host) into the full feature-extraction pipeline.
#include "FPEngine.cc"

#include <cstdio>
#include <cstdlib>

// Global options object (normally in nmap.cc)
NmapOps o;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 8) return 0;

  FingerPrintResultsIPv6 fpr;
  struct timeval tv = {0, 0};

  // Split hostile data across a rotating subset of probe responses
  const char *names[] = {"S1", "S2", "S3", "S4", "S5", "S6",
                          "IE1", "IE2", "NS", "U1", "TECN",
                          "T2", "T3", "T4", "T5", "T6", "T7"};
  int nnames = (int) (sizeof(names) / sizeof(names[0]));

  // choose 1-4 responses based on first byte
  int nresp = 1 + (data[0] & 3);
  for (int i = 0; i < nresp && i < nnames; i++) {
    size_t off = (i * 7 + 3) % (size > 16 ? size - 8 : 1);
    size_t len = size - off > 64 ? 64 : size - off;
    if (len < 4) len = size > 4 ? 4 : size;
    const char *id = names[(data[i % 4] % nnames)];
    fpr.fp_responses[i % NUM_FP_PROBES_IPv6] =
        new FPResponse(id, (const u8 *) (data + off), len, tv, tv);
  }

  // run the static vectorize pipeline on the hostile responses
  struct feature_node *features = vectorize(&fpr);
  if (features != NULL) {
    free(features);
  }

  // cleanup responses
  for (int i = 0; i < NUM_FP_PROBES_IPv6; i++) {
    if (fpr.fp_responses[i] != NULL) {
      delete fpr.fp_responses[i];
      fpr.fp_responses[i] = NULL;
    }
  }
  return 0;
}
