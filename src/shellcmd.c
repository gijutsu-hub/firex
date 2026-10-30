#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shellcmd.h"
#include "brand.h"

static unsigned failures = 0;

int fx_run(const char *cmd)
{
    int rc = system(cmd);

    if (rc == -1) {
        fprintf(stderr, "[%s] could not run: %s\n", BRAND_PRODUCT, cmd);
        failures++;
        return -1;
    }
    if (rc != 0) {
        /* A caller that redirected stderr away already expects this command
         * to fail routinely (deleting a rule that is not there), so stay
         * quiet for those and only report the ones that matter. */
        if (!strstr(cmd, "2>/dev/null")) {
            fprintf(stderr, "[%s] command exited %d: %s\n",
                    BRAND_PRODUCT, rc / 256, cmd);
            failures++;
        }
    }
    return rc;
}

int fx_try(const char *cmd)
{
    int rc = system(cmd);
    return rc == -1 ? -1 : rc;
}

unsigned fx_run_failures(void)
{
    return failures;
}
