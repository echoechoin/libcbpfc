/*
 * err.c - the message behind a failure.
 *
 * The functions that fail return NULL or -1, which says nothing about why;
 * the answer lives here, the way it does in curl or sqlite. It is per-thread,
 * so two threads reporting failures do not overwrite each other.
 *
 * The buffer is fixed, and only the last failure is kept - reading it later
 * than the next cbpfc_* call on the same thread gets the newer message.
 */
#include <stdarg.h>
#include <stdio.h>

#include "cbpfc.h"
#include "internal.h"

#define ERR_MAX 256

static _Thread_local char last[ERR_MAX];

const char *cbpfc_errmsg(void)
{
	return last;
}

void cbpfc_err_set(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(last, sizeof(last), fmt, ap);
	va_end(ap);
}

void cbpfc_err_clear(void)
{
	last[0] = '\0';
}
