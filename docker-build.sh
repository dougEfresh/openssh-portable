#!/bin/bash
#--privileged -v /sys/fs/cgroup:/sys/fs/cgroup:ro
docker run -it -w /root/rpmbuild/SPECS \
       -v $PWD/contrib/passwd-pot/rpmbuild:/root/rpmbuild \
       -v $PWD:/root/build dougefresh/amazonlinux-devel:latest sh -c 'chown root:root *.spec ; rpmbuild -ba *.spec'
let exitCode=$?
find . -uid 0 | xargs sudo chown  $USER
exit $exitCode
