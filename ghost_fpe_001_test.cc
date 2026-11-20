#include "FPEngine.cc"
#include <cstdio>
#include <cmath>
extern NmapOps o;

static std::map<std::string, FPPacket> resps_from_fpr(FingerPrintResultsIPv6 *fpr) {
  std::map<std::string, FPPacket> resps;
  for (int i = 0; i < NUM_FP_PROBES_IPv6; i++) {
    if (fpr->fp_responses[i] == NULL) continue;
    PacketElement *pe = PacketParser::split(fpr->fp_responses[i]->buf, fpr->fp_responses[i]->len);
    assert(pe != NULL);
    resps[fpr->fp_responses[i]->probe_id].setPacket(pe);
    resps[fpr->fp_responses[i]->probe_id].setTime(&fpr->fp_responses[i]->senttime);
  }
  return resps;
}

int main() {
  // Simulate 6 SEQ responses with IDENTICAL timestamps (same microsecond)
  // and IDENTICAL seq numbers — the hostile t=0.0 sum=0 scenario.
  struct FingerPrintResultsIPv6 fpr;
  struct timeval tv = {1000, 500000};
  const char *names[] = {"S1","S2","S3","S4","S5","S6"};
  for (int i = 0; i < 6; i++) {
    // TCP SYN-ACK packet with same seq 0xDEADBEEF every time
    u8 pkt[] = {
      0x60,0x00,0x00,0x00,0x00,0x14,0x06,0x40,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,
      0x04,0xd2,0x00,0x50,0xde,0xad,0xbe,0xef,0x00,0x00,0x00,0x00,
      0x50,0x12,0x16,0xd0,0x00,0x00,0x00,0x00
    };
    fpr.fp_responses[i] = new FPResponse(names[i], pkt, sizeof(pkt), tv, tv);
  }
  // vectorize is static; call through the same path: use the exported one
  struct feature_node *features = vectorize(&fpr);
  auto resps_map = resps_from_fpr(&fpr);
  double direct_isr = vectorize_isr(resps_map);
  printf("DIRECT vectorize_isr = %f\n", direct_isr);
  if (std::isnan(direct_isr)) printf("*** NaN CONFIRMED: GHOST-FPE-001 REAL ***\n");
  if (std::isinf(direct_isr)) printf("*** INF CONFIRMED: GHOST-FPE-001 REAL ***\n");
  for (int k = 0; k < 16; k++)
    printf("feature[%d] = %f%s%s\n", k, features[k].value,
           std::isnan(features[k].value) ? " <-- NaN!" : "",
           std::isinf(features[k].value) ? " <-- INF!" : "");
  printf("sanity: 0.0/0.0 = %f, 5.0/0.0 = %f\n", 0.0/0.0, 5.0/0.0);
  return 0;
}
