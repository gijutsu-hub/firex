#ifndef FIREX_SHELLCMD_H
#define FIREX_SHELLCMD_H

/*
 * Thin wrapper around system() for the provisioning paths.
 *
 * fx_run()  runs the command and reports a non-zero exit, so a failed
 *           "ip link add" or iptables insertion is visible instead of silent.
 * fx_try()  is for best-effort calls that are expected to fail routinely
 *           (deleting a chain that was never created, for example).
 *
 * Neither builds a command from untrusted input on its own: callers must
 * validate anything that reaches the shell.
 */
int fx_run(const char *cmd);
int fx_try(const char *cmd);

/* Number of fx_run() calls that reported failure since startup. */
unsigned fx_run_failures(void);

#endif
