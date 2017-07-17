#!/bin/bash
dire="./15-441-project-1"
if [ -d "$dire" ]; then
  rm -r "$dire"
  mkdir "$dire"
else
  mkdir "$dire"
fi

tarfile="./15-441-project-1-cp2.tar"
if [ -f "$tarfile" ]; then
  rm "$tarfile"
fi

cp lisod.c "$dire"
cp lisod.h "$dire"
cp log.c "$dire"
cp lexer.l "$dire"
cp parser.y "$dire"
cp parse.c "$dire"
cp time_now.c "$dire"
cp Makefile "$dire"
cp -r .git "$dire"
tar -cvf "$tarfile" "$dire"