/*
 * internal.h - shared between the library's translation units, not installed.
 */
#ifndef CBPFC_INTERNAL_H
#define CBPFC_INTERNAL_H

/* Record the message cbpfc_errmsg() returns. Every public entry point that can
 * fail clears it first, so what comes back is always from the call that just
 * failed. */
void cbpfc_err_set(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

void cbpfc_err_clear(void);

#endif /* CBPFC_INTERNAL_H */
