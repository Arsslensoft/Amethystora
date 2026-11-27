# vim: set ft=make :

set default-list

# A database or a mail catcher for a project in one line. ACTION: add NAME [AS] (postgres, mariadb, valkey (or redis), mailpit; --port N, --at-login), start AS, stop AS, remove AS (the data goes only if you say so, in a terminal), or list [--json]. It runs in a container of your own and listens on this computer only
[positional-arguments]
service ACTION="" *ARGS:
    @/usr/libexec/amethystora-dev-services "$@"

# Which program or container listens on which port, in which project folder; your own only, the rest is "another account" (--json for a program)
[positional-arguments]
ports *ARGS:
    @/usr/libexec/amethystora-dev-services ports "$@"

# Whether a graphics card can be used by a container here (CUDA, ROCm, the render node), step by step, changing nothing. --pull fetches the small image the container step runs, after saying its size; --deep runs a short computation in it (NVIDIA only); --json for a program
[positional-arguments]
gpu *ARGS:
    @/usr/libexec/amethystora-gpu-compute "$@"
