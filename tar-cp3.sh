#!/bin/bash
dire="15-441-project-1"
if [ -d "$dire" ]; then
  rm -r "$dire"
  mkdir "$dire"
else
  mkdir "$dire"
fi

tarfile="15-441-project-1-cp3.tar"
if [ -f "$tarfile" ]; then
  rm "$tarfile"
fi

cp lisod.c "$dire"
cp lisod.h "$dire"
cp log.c "$dire"
cp log.h "$dire"
cp cgi_func.c "$dire"
cp dbg_func.c "$dire"
cp dbg_func.h "$dire"
cp lexer.l "$dire"
cp parser.y "$dire"
cp parse.c "$dire"
cp time_gmt.c "$dire"
cp daemonize.c "$dire"
cp Makefile "$dire"
cp readme.txt "$dire"
cp test.txt "$dire"
cp vulnerabilities.txt "$dire"
cp sslcrt.crt "$dire"
cp sslkey.key "$dire"
cp -r flaskr "$dire"
cp -r .git "$dire"
tar -cvf "$tarfile" "$dire"