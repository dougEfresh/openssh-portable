rm -rf build
mkdir build
docker run  -ti -v $PWD/build:/opt/ssh -v $PWD:/root/build dougefresh/alpine:3.7  sh -c 'make distclean ;  autoconf -f && autoheader -f && ./configure \
--disable-suid-ssh\
 --without-stackprotect\
 --without-hardening\
 --with-ssl-engine\
 --disable-lastlog\
 --disable-wtmp\
 --without-rsh\
 --with-privsep-user=nobody\
 --prefix=/opt/ssh\
 --with-audit-passwd-url=yes && make clean && make -j 4 && make install' && \
find . -uid 0 | xargs sudo chown  $USER
