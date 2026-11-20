#include <cstdio>
int nmap_fetchfile(char *buf, int buflen, const char *file) {
  (void) buf; (void) buflen; (void) file; return 0;
}
const char *MACPrefix2Corp(const unsigned char *mac) { (void) mac; return "Unknown"; }
char *ippackethdrinfo(const unsigned char *packet, unsigned int len, int detail) {
  (void) packet; (void) detail;
  static char buf[512];
  snprintf(buf, sizeof(buf), "[pkt %u B]", len);
  return buf;
}
bool keyWasPressed() { return false; }
char *format_ip_options(const unsigned char *ipopt, int optlen) {
  (void) ipopt;
  static char buf[1024];
  int pos = 0;
  for (int i = 0; i < optlen && pos < (int) sizeof(buf) - 8; i++)
    pos += snprintf(buf + pos, sizeof(buf) - pos, "%02x", ipopt[i]);
  buf[pos] = '\0';
  return buf;
}
