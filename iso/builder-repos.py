#!/usr/bin/python3
# Run inside the pinned bootc-image-builder container (.github/workflows/build-iso.yml), before it
# starts. The builder picks the installer's packages with osbuild's dnf 4 solver, from the repositories
# of the image itself, which it reads from <image>/etc/yum.repos.d alone. Fedora 45 moved its own
# repository files to /usr/share/dnf5/repos.d (https://fedoraproject.org/wiki/Changes/RelocateRpmRepoConfigsToUsr),
# so the builder finds no repository at all (osbuild/image-builder#2704), and dnf 4 does not know the
# overrides in /etc/dnf/repos.override.d either, through which the image turns RPM Fusion and openh264
# off. This changes the solver to read the folders the image's own dnf5 reads, and to apply those
# overrides' enabled= after, so that the installer is made of what the image's dnf would install from:
# Fedora's repositories only. It fails if the solver is not the one it was written against.
import pathlib
import sys

SOLVER = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else
                      "/usr/lib/python3.13/site-packages/osbuild/solver/dnf.py")

OLD = """                repos_dir = os.path.join(self.root_dir, "etc/yum.repos.d")
                self.base.conf.reposdir = repos_dir
                self.base.read_all_repos()
"""

NEW = """                # Changed by Amethystora (iso/builder-repos.py): the folders dnf5 reads, and its overrides
                self.base.conf.reposdir = [
                    os.path.join(self.root_dir, folder)
                    for folder in ("etc/yum.repos.d", "etc/distro.repos.d", "usr/share/dnf5/repos.d")
                    if os.path.isdir(os.path.join(self.root_dir, folder))
                ]
                self.base.read_all_repos()
                _amethystora_overrides(self.base, self.root_dir)
"""

HELPER = '''

# Added by Amethystora (iso/builder-repos.py): dnf5's repos.override.d, read in its order (by file name),
# a later file winning; a section names repositories by a glob, as dnf5 reads it. Only enabled= is applied.
def _amethystora_overrides(base, root_dir):
    import configparser
    import fnmatch
    folder = os.path.join(root_dir, "etc/dnf/repos.override.d")
    if not os.path.isdir(folder):
        return
    for name in sorted(os.listdir(folder)):
        if not name.endswith(".repo"):
            continue
        parser = configparser.ConfigParser(interpolation=None)
        parser.read(os.path.join(folder, name))
        for section in parser.sections():
            if "enabled" not in parser[section]:
                continue
            enabled = parser[section].getboolean("enabled")
            for repo_id, repo in base.repos.items():
                if fnmatch.fnmatchcase(repo_id, section):
                    if enabled:
                        repo.enable()
                    else:
                        repo.disable()
'''

text = SOLVER.read_text()
if text.count(OLD) != 1:
    sys.exit(f"{SOLVER}: not the solver iso/builder-repos.py was written for")
SOLVER.write_text(text.replace(OLD, NEW) + HELPER)
