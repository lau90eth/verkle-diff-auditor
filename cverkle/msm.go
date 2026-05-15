package cverkle

/*
#cgo LDFLAGS: -L${SRCDIR} -lc_verkle -Wl,-rpath,${SRCDIR}
#include "c_verkle.h"
#include "wrapper.c"
#include <stdlib.h>

void wrapper_msm(const uint8_t *scalars, size_t len, uint8_t *out);
