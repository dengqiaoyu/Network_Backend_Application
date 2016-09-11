#!/bin/bash
dire="./15-441-project-1"
if [ -d "$dire" ]; then
  rm -r "$dire"
  mkdir "$dire"
else
  mkdir "$dire"
fi

tarfile="./15-441-project-1-cp1.tar"
if [ -f "$tarfile" ]; then
  rm "$tarfile"
fi

cp lisod.c "$dire"
cp lisod.h "$dire"
cp log.c "$dire"
cp log.h "$dire"
cp Makefile "$dire"
tar -cvf "$tarfile" "$dire"