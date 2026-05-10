/**
 * @file syscalls.c
 * @author Alex Anderson (aandrs@vt.edu)
 * @brief Newlib bare-metal syscall stubs for TM4C123GH6PM
 * @version 0.1
 * @date 2026-05-09
 * 
 * @copyright Copyright (c) 2026
 * 
 */

#include <stdint.h>
#include <sys/stat.h>

void _exit(int status) { (void)status; while(1); }
void *_sbrk(int incr) { (void)incr; return (void *)-1; }
int _close(int fd) { (void)fd; return -1; }
int _fstat(int fd, struct stat *st) { (void)fd; st->st_mode = S_IFCHR; return 0; }
int _isatty(int fd) { (void)fd; return 1; }
int _lseek(int fd, int offset, int whence) { (void)fd; (void)offset; (void)whence; return 0; }
int _read(int fd, char *buf, int len) { (void)fd; (void)buf; (void)len; return 0; }
int _write(int fd, char *buf, int len) { (void)fd; (void)buf; (void)len; return 0; }
