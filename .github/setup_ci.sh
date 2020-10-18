#!/usr/bin/env bash

pacman -S  -u --noprogressbar --noconfirm
pacman -S --noconfirm --noprogressbar 'glibc' 'krb5' 'openssl' 'libedit' 'ldns' 'libxcrypt' 'libcrypt.so' 'zlib' 'pam' make gcc
