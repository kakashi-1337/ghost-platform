// Stubs for nmap-core functions referenced by libnetutil header classes,
// so the fuzzer harness can link without the full nmap object graph.
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include "targets.h"
#include "tcpip.h"

extern "C" {

// netutil fatal/error helpers
void netutil_fatal(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
  exit(1);
}

void netutil_error(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}

void netutil_debug(const char *fmt, ...) {
  (void) fmt;
}

}  // extern "C"

// format_ip_options: C++ linkage (matches mangled symbol in libnetutil).
// Minimal safe implementation used only by print paths.
char *format_ip_options(const unsigned char *ipopt, int optlen) {
  static char buf[1024];
  int pos = 0;
  for (int i = 0; i < optlen && pos < (int) sizeof(buf) - 8; i++) {
    pos += snprintf(buf + pos, sizeof(buf) - pos, "%02x", ipopt[i]);
  }
  if (pos >= (int) sizeof(buf)) pos = sizeof(buf) - 1;
  buf[pos] = '\0';
  return buf;
}

// ippackethdrinfo: C++ linkage stub (print-only path)
char *ippackethdrinfo(const unsigned char *packet, unsigned int len, int detail) {
  static char buf[512];
  snprintf(buf, sizeof(buf), "[pkt %u B]", len);
  (void) packet; (void) detail;
  return buf;
}

// nmap_fetchfile stub: C++ linkage, return not-found
int nmap_fetchfile(char *buf, int buflen, const char *file) {
  (void) buf; (void) buflen; (void) file;
  return 0;
}

// keyWasPressed stub (console interaction, C++ linkage)
bool keyWasPressed() { return false; }



// output.cc helpers
const char *MACPrefix2Corp(const unsigned char *mac) {
  (void) mac;
  return "Unknown";
}
