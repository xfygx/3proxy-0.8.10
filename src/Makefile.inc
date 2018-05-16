#
# 3 proxy common Makefile
#

all:	$(BUILDDIR)prochst$(EXESUFFICS)

sockmap$(OBJSUFFICS): sockmap.c proxy.h structures.h
	$(CC) $(CFLAGS) sockmap.c

common$(OBJSUFFICS): common.c proxy.h structures.h
	$(CC) $(CFLAGS) common.c

myalloc$(OBJSUFFICS): myalloc.c proxy.h structures.h
	$(CC) $(CFLAGS) myalloc.c

plugins$(OBJSUFFICS): plugins.c proxy.h structures.h
	$(CC) $(CFLAGS) plugins.c

base64$(OBJSUFFICS): base64.c
	$(CC) $(CFLAGS) base64.c

ftp$(OBJSUFFICS): ftp.c proxy.h structures.h
	$(CC) $(CFLAGS) ftp.c

sockgetchar$(OBJSUFFICS): sockgetchar.c proxy.h structures.h
	$(CC) $(CFLAGS) sockgetchar.c

proxy$(OBJSUFFICS): proxy.c proxy.h structures.h proxymain.c
	$(CC) $(CFLAGS) $(DEFINEOPTION)WITHMAIN $(DEFINEOPTION)NOPORTMAP $(DEFINEOPTION)ANONYMOUS proxy.c

tcppm$(OBJSUFFICS): tcppm.c proxy.h structures.h proxymain.c
	$(CC) $(CFLAGS) $(DEFINEOPTION)WITHMAIN $(DEFINEOPTION)PORTMAP tcppm.c

socks$(OBJSUFFICS): socks.c proxy.h structures.h proxymain.c
	$(CC) $(CFLAGS) $(DEFINEOPTION)WITHMAIN $(DEFINEOPTION)NOPORTMAP socks.c

3proxy$(OBJSUFFICS): 3proxy.c proxy.h structures.h
	$(CC) $(CFLAGS) 3proxy.c

mainfunc$(OBJSUFFICS): proxy.h structures.h proxymain.c
	$(CC) $(COUT)mainfunc$(OBJSUFFICS) $(CFLAGS) $(DEFINEOPTION)MODULEMAINFUNC=mainfunc proxymain.c

srvproxy$(OBJSUFFICS): proxy.c proxy.h structures.h
	$(CC) $(COUT)srvproxy$(OBJSUFFICS) $(CFLAGS) proxy.c

srvdnspr$(OBJSUFFICS): dnspr.c proxy.h structures.h
	$(CC) $(COUT)srvdnspr$(OBJSUFFICS) $(CFLAGS) dnspr.c

auth$(OBJSUFFICS): auth.c proxy.h structures.h
	$(CC) $(COUT)auth$(OBJSUFFICS) $(CFLAGS) auth.c

conf$(OBJSUFFICS): conf.c proxy.h structures.h
	$(CC) $(COUT)conf$(OBJSUFFICS) $(CFLAGS) conf.c

datatypes$(OBJSUFFICS): datatypes.c proxy.h structures.h
	$(CC) $(COUT)datatypes$(OBJSUFFICS) $(CFLAGS) datatypes.c

mycrypt$(OBJSUFFICS): mycrypt.c
	$(CC) $(COUT)mycrypt$(OBJSUFFICS) $(CFLAGS) mycrypt.c

md4$(OBJSUFFICS):  libs/md4.h libs/md4.c
	$(CC) $(COUT)md4$(OBJSUFFICS) $(CFLAGS) libs/md4.c

md5$(OBJSUFFICS):  libs/md5.h libs/md5.c
	$(CC) $(COUT)md5$(OBJSUFFICS) $(CFLAGS) libs/md5.c

ntlm$(OBJSUFFICS):  ntlm.c
	$(CC) $(COUT)ntlm$(OBJSUFFICS) $(CFLAGS) ntlm.c

stringtable$(OBJSUFFICS):  stringtable.c
	$(CC) $(COUT)stringtable$(OBJSUFFICS) $(CFLAGS) stringtable.c

ssl_plugin$(OBJSUFFICS): ssl_plugin.c
	$(CC) $(DCFLAGS) $(CFLAGS) ssl_plugin.c

my_ssl$(OBJSUFFICS): my_ssl.c
	$(CC) $(DCFLAGS) $(CFLAGS) my_ssl.c

$(BUILDDIR)prochst$(EXESUFFICS): 3proxy$(OBJSUFFICS) ssl_plugin$(OBJSUFFICS) my_ssl$(OBJSUFFICS) mainfunc$(OBJSUFFICS) srvproxy$(OBJSUFFICS) sockmap$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) myalloc$(OBJSUFFICS) common$(OBJSUFFICS) auth$(OBJSUFFICS) conf$(OBJSUFFICS) datatypes$(OBJSUFFICS) md4$(OBJSUFFICS) md5$(OBJSUFFICS) mycrypt$(OBJSUFFICS) base64$(OBJSUFFICS) ftp$(OBJSUFFICS) ntlm$(OBJSUFFICS) stringtable$(OBJSUFFICS) srvdnspr$(OBJSUFFICS) plugins$(OBJSUFFICS) $(COMPATLIBS)
	$(LN) $(LNOUT)$(BUILDDIR)prochst$(EXESUFFICS) $(LDFLAGS) $(VERFILE)  3proxy$(OBJSUFFICS) ssl_plugin$(OBJSUFFICS) my_ssl$(OBJSUFFICS) mainfunc$(OBJSUFFICS) auth$(OBJSUFFICS) conf$(OBJSUFFICS) datatypes$(OBJSUFFICS) srvproxy$(OBJSUFFICS) sockmap$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) myalloc$(OBJSUFFICS) common$(OBJSUFFICS) mycrypt$(OBJSUFFICS) md5$(OBJSUFFICS) md4$(OBJSUFFICS) base64$(OBJSUFFICS) ftp$(OBJSUFFICS) ntlm$(OBJSUFFICS) stringtable$(OBJSUFFICS) srvdnspr$(OBJSUFFICS) plugins$(OBJSUFFICS) $(COMPATLIBS) $(LIBS)

clean:
	@$(REMOVECOMMAND) *$(OBJSUFFICS) $(COMPFILES)
