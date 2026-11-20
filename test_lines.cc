#include "service_scan.cc"
extern NmapOps o;
int main() {
  const char *lines[] = {
    "match fuzz1 m|^FUZZ1(.*?)ZZ$|s p/Fuzz One/ v/$1/ i/data $1/ ",
    "match fuzz2 m|^FUZZ2(.*?)ZZ$|s p/Fuzz Two/ v/$SUBST(1,\"QQQQQ\",\"Y\")/ i/sub $1/ ",
    "match fuzz3 m|^FUZZ3(.*?)ZZ$|s p/Fuzz Three/ v/$P(1)/ i/int $I(1,'>')/ ",
    "match fuzz4 m|^FUZZ4(.*?)ZZ$|s p/Fuzz Four/ v/$1/ h/$1/ o/$1/ d/$1/ cpe:/a:ven:p:$1/ ",
  };
  for (int i = 0; i < 4; i++) {
    printf("testing line %d...\n", i);
    fflush(stdout);
    ServiceProbeMatch *m = new ServiceProbeMatch();
    m->InitMatch(lines[i], 100 + i);
    printf("  line %d OK\n", i);
  }
  printf("ALL OK\n");
  return 0;
}
