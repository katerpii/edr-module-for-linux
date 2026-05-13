#include <string.h>
#include "r001_shell_from_service.h"

static const char *SHELLS[] = {
    "bash", "sh", "zsh", "dash", "ash", "fish", NULL
};

static const char *SERVICES[] = {
    "nginx", "apache2", "httpd", "php", "php-fpm",
    "python", "python3", "ruby", "node", "java",
    "sshd", "vsftpd", "mysqld", "postgres",
    NULL
};

static int in_list(const char *s, const char **list)
{
    for (int i = 0; list[i]; i++)
        if (strncmp(s, list[i], COMM_LEN) == 0) return 1;
    return 0;
}

static int evaluate(const struct event *e, int64_t start_ts, int64_t event_id)
{
    (void)start_ts; (void)event_id;
    if (e->type != evt_exec) return 0;
    return in_list(e->comm, SHELLS) && in_list(e->p_comm, SERVICES);
}

const rule_t r001_shell_from_service = {
    .id       = "R001_SHELL_FROM_SERVICE",
    .severity = 3,
    .evaluate = evaluate,
};
