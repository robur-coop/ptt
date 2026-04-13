#ifndef __unused
#if defined(_MSC_VER) && _MSC_VER >= 1500
#define __unused(x)                                                            \
  __pragma(warning(push)) __pragma(warning(disable : 4189)) x __pragma(        \
      warning(pop))
#else
#define __unused(x) x __attribute((unused))
#endif
#endif

#define __unit() value __unused(unit)
#include <caml/bigarray.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <caml/unixsupport.h>
#include <unistd.h>

CAMLprim value ptt_getpagesize(__unit()) { return (Val_long(getpagesize())); }

CAMLprim value ptt_pread(value vfd, value vbuf, value voff, value vlen,
                         value vat) {
  CAMLparam5(vfd, vbuf, voff, vlen, vat);
  intnat off, len, at, ret;
  int fd;
  void *buf;

  buf = Caml_ba_data_val(vbuf);
  off = Long_val(voff);
  len = Long_val(vlen);
  at = Long_val(vat);
  fd = Int_val(vfd);
  caml_enter_blocking_section();
  ret = pread(fd, (char *)buf + off, len, at);
  caml_leave_blocking_section();
  if (ret == -1)
    caml_uerror("mkfs_pread", Nothing);
  CAMLreturn(Val_long(ret));
}

CAMLprim value ptt_pwrite(value vfd, value vbuf, value voff, value vlen,
                          value vat) {
  CAMLparam5(vfd, vbuf, voff, vlen, vat);
  intnat off, len, at, ret;
  int fd;
  void *buf;

  buf = Caml_ba_data_val(vbuf);
  off = Long_val(voff);
  len = Long_val(vlen);
  at = Long_val(vat);
  fd = Int_val(vfd);
  caml_enter_blocking_section();
  ret = pwrite(fd, (char *)buf + off, len, at);
  caml_leave_blocking_section();
  if (ret == -1)
    caml_uerror("mkfs_pwrite", Nothing);
  CAMLreturn(Val_long(ret));
}
