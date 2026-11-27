#!/usr/bin/bash
# Move in from Windows: /usr/libexec/amethystora-move-in against stand-ins, run from 20-tests.sh and by hand
# (`bash build_files/shared/test-move-in.sh [HELPER]`). A Windows disk is a folder tree here, lsblk, findmnt and udisksctl are stubs that
# log what they were asked, the helper is loaded as a module so that the few things only a real disk or a real person gives (the unlock, the
# administrator check, a file's Windows attributes, the pill) can be put in its place, and the copy is the real one. It checks what the helper
# promises:
#  - a disk is only ever asked for as `ro,noexec,nosuid,nodev`, only a disk the partition table shows could hold Windows is opened, a disk
#    the desktop mounted read-write is unmounted first, and what the disk holds is the same bytes afterwards
#  - the offer mounts nothing; accounts are listed to an administrator only, and anyone else sees their own
#  - a BitLocker volume is unlocked with its key handed over once, read-only or not at all, and the key is nowhere afterwards
#  - the five folders only (no Downloads, no AppData, no password store), OneDrive's too, links and junk passed over
#  - a file that is already in the home is never replaced: the copy lands beside it; a second run, and a run after a stop, copy only what
#    is missing; a placeholder is skipped and counted; nothing half written is left; the pill is started, updated and ended, with no name in it
set -uo pipefail

HELPER="${1:-$(dirname "$0")/../../system_files/shared/usr/libexec/amethystora-move-in}"
T="$(mktemp -d)"
trap 'chmod -R u+rwX "${T}" 2>/dev/null; rm -rf "${T}"' EXIT
fail() {
    echo "test-move-in: $*" >&2
    exit 1
}
[[ -f "${HELPER}" ]] || fail "no helper at ${HELPER}"
python3 -I -c "import ast,sys; ast.parse(open(sys.argv[1], encoding='utf-8').read())" "${HELPER}" || fail "the helper does not parse"

WIN="${T}/win"
HOME_ONE="${T}/home1"
mkdir -p "${T}/stubs" "${T}/run" "${HOME_ONE}"
chmod 700 "${T}/run"
export PATH="${T}/stubs:${PATH}" XDG_RUNTIME_DIR="${T}/run" HOME="${HOME_ONE}" XDG_STATE_HOME="${T}/state"
unset XDG_CONFIG_HOME XDG_DATA_HOME

# --- A Windows disk's stand-in ------------------------------------------------------------------------------------------------------
SAM="${WIN}/Users/Sam"
mkdir -p "${WIN}/Windows/System32" "${SAM}/Documents/letters" "${SAM}/Pictures" "${SAM}/Music" "${SAM}/Videos" "${SAM}/Desktop" "${SAM}/Downloads" \
    "${SAM}/OneDrive/Documents" "${SAM}/OneDrive/Pictures" "${SAM}/AppData/Local/Google/Chrome/User Data/Default" "${WIN}/Users/Pat/Documents" \
    "${WIN}/Users/Public/Documents" "${WIN}/Users/Default"
mkdir -p "${T}/data/Photos"
echo "not Windows" >"${T}/data/Photos/x.jpg"
: >"${SAM}/NTUSER.DAT"
: >"${WIN}/Users/Pat/NTUSER.DAT"
echo "the report, Windows' copy" >"${SAM}/Documents/report.docx"
echo "dear Sam" >"${SAM}/Documents/letters/a.txt"
echo hidden >"${SAM}/Documents/desktop.ini"
echo thumbs >"${SAM}/Documents/Thumbs.db"
echo lock >"${SAM}/Documents/~\$report.docx"
head -c 300000 /dev/zero >"${SAM}/Music/song.mp3"
echo "a picture" >"${SAM}/Pictures/p.jpg"
echo "a film" >"${SAM}/Videos/v.mp4"
echo "on the desktop" >"${SAM}/Desktop/todo.txt"
echo "an installer" >"${SAM}/Downloads/setup.exe"
echo "a file Pat only has" >"${WIN}/Users/Pat/Documents/pat.txt"
echo "CANARY-CHROME-PASSWORD" >"${SAM}/AppData/Local/Google/Chrome/User Data/Default/Login Data"
ln -s /etc/hostname "${SAM}/Documents/hostname-link"
ln -s /etc "${SAM}/Documents/etc-folder"
echo "synced and here" >"${SAM}/OneDrive/Documents/synced.txt"
echo "downloaded" >"${SAM}/OneDrive/Pictures/there.jpg"
# Two files that are only in OneDrive: one the driver says so of (attribute), one it does not (a size with no blocks behind it)
echo "remote" >"${SAM}/OneDrive/Documents/attr-placeholder.docx"
truncate -s 5000 "${SAM}/OneDrive/Documents/sparse-placeholder.docx"
find "${WIN}" -type f -printf '%P %s %T@\n' | sort | cksum >"${T}/win.sum"
disk_sum() { find "${WIN}" -type f -printf '%P %s %T@\n' | sort | cksum; }

# --- The disks, as lsblk shows them, and the stubs --------------------------------------------------------------------------------------
GIB=$((1 << 30))
cat >"${T}/tree.json" <<JSON
{"blockdevices":[
 {"name":"sda","path":"/dev/sda","type":"disk","fstype":null,"size":$((200 * GIB)),"rm":false,"ro":false,"model":"WIN DISK","pkname":null,"tran":"sata","mountpoints":[null],"children":[
  {"name":"sda1","path":"/dev/sda1","type":"part","fstype":"vfat","size":$((GIB / 4)),"label":"SYSTEM","pkname":"sda","parttype":"c12a7328-f81f-11d2-ba4b-00a0c93ec93b","mountpoints":[null]},
  {"name":"sda2","path":"/dev/sda2","type":"part","fstype":"ntfs","size":$((150 * GIB)),"label":"Windows","uuid":"AAAA-1111","pkname":"sda","parttype":"ebd0a0a2-b9e5-4433-87c0-68b6b72699c7","mountpoints":[null]},
  {"name":"sda3","path":"/dev/sda3","type":"part","fstype":"ntfs","size":$((GIB / 2)),"label":"Recovery","pkname":"sda","parttype":"de94bba4-06d1-4d40-a16a-bfd50179d6ac","mountpoints":[null]},
  {"name":"sda4","path":"/dev/sda4","type":"part","fstype":"ntfs","size":$((GIB / 2)),"label":"System Reserved","pkname":"sda","parttype":"ebd0a0a2-b9e5-4433-87c0-68b6b72699c7","mountpoints":[null]}]},
 {"name":"sdb","path":"/dev/sdb","type":"disk","fstype":null,"size":$((100 * GIB)),"rm":false,"model":"THIS ONE","tran":"sata","mountpoints":[null],"children":[
  {"name":"sdb1","path":"/dev/sdb1","type":"part","fstype":"btrfs","size":$((90 * GIB)),"pkname":"sdb","mountpoints":["/var","/"]},
  {"name":"sdb2","path":"/dev/sdb2","type":"part","fstype":"ntfs","size":$((10 * GIB)),"label":"Games","pkname":"sdb","mountpoints":[null]}]},
 {"name":"sdc","path":"/dev/sdc","type":"disk","fstype":null,"size":$((500 * GIB)),"rm":true,"model":"USB","tran":"usb","mountpoints":[null],"children":[
  {"name":"sdc1","path":"/dev/sdc1","type":"part","fstype":"BitLocker","size":$((400 * GIB)),"uuid":"BBBB-2222","pkname":"sdc","mountpoints":[null]}]},
 {"name":"sdd","path":"/dev/sdd","type":"disk","fstype":"ntfs","size":$((8 * GIB)),"label":"Data","pkname":null,"mountpoints":[null]}
]}
JSON
# Windows beside this system on its own disk (sdb2) counts; the volume this system runs from (sdb1), the recovery and boot stubs do not
cat >"${T}/stubs/lsblk" <<EOF
#!/usr/bin/bash
echo "\$*" >>"${T}/lsblk.log"
case "\$*" in
    *NAME,PATH,FSTYPE*) cat "${T}/tree.json" ;;
    *PATH,TYPE*)
        if [[ -e "${T}/crypt.json" ]]; then cat "${T}/crypt.json"; else echo '{"blockdevices":[{"path":"'"\${@: -1}"'","type":"part"}]}'; fi ;;
    *PATH,MOUNTPOINTS*)
        if [[ -e "${T}/mounted" ]]; then
            echo '{"blockdevices":[{"path":"'"\${@: -1}"'","mountpoints":["'"\$(cat "${T}/mounted")"'"]}]}'
        else
            echo '{"blockdevices":[{"path":"'"\${@: -1}"'","mountpoints":[null]}]}'
        fi ;;
    *"-o RO"*) echo "\$(cat "${T}/ro" 2>/dev/null || echo 1)" ;;
    *) exit 1 ;;
esac
EOF
cat >"${T}/stubs/findmnt" <<EOF
#!/usr/bin/bash
echo "\$*" >>"${T}/findmnt.log"
echo "\$(cat "${T}/mountopts" 2>/dev/null || echo ro,noexec,nosuid,nodev,relatime)"
EOF
cat >"${T}/stubs/udisksctl" <<EOF
#!/usr/bin/bash
echo "\$*" >>"${T}/udisks.log"
case "\$1" in
    mount) dir="${WIN}"; [[ "\${3}" == /dev/sdb2 || "\${3}" == /dev/sdd ]] && dir="${T}/data"; echo "\${dir}" >"${T}/mounted"; echo "Mounted \${3} at \${dir}." ;;
    unmount) [[ -e "${T}/busy" ]] && { echo "Error unmounting \${3}: target is busy" >&2; exit 1; }; rm -f "${T}/mounted"; echo "Unmounted \${3}." ;;
    *) exit 1 ;;
esac
EOF
cat >"${T}/stubs/pill" <<EOF
#!/usr/bin/bash
echo "\$*" >>"${T}/pill.log"
EOF
chmod +x "${T}/stubs/"*

# --- The helper, as a module -------------------------------------------------------------------------------------------------------------
cat >"${T}/driver.py" <<'PY'
import contextlib, io, importlib.machinery, importlib.util, json, os, shutil, subprocess, sys

helper, t, win = sys.argv[1:4]
loader = importlib.machinery.SourceFileLoader("move_in", helper)
spec = importlib.util.spec_from_loader("move_in", loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)
mod.PILL = os.path.join(t, "stubs", "pill")

failures = []


asked = []


def check(name, condition, detail=""):
    asked.append(name)
    if not condition:
        failures.append(f"{name} {detail}".strip())
        print(f"FAIL {name} {detail}", file=sys.stderr)


def call(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = mod.main(["amethystora-move-in", *args])
    if ("--json" in args or "--offer" in args) and code == 0:
        try:
            json.loads(out.getvalue())
        except ValueError:
            check("only JSON reaches standard output with --json", False, out.getvalue()[:300])
    return code, out.getvalue(), err.getvalue()


HOME1, STATE1 = os.environ["HOME"], os.environ["XDG_STATE_HOME"]


def use_home(name):
    """A home of its own, with its own record of what was copied"""
    path = os.path.join(t, name)
    os.makedirs(path, exist_ok=True)
    mod.HOME = path
    os.environ["HOME"] = path
    os.environ["XDG_STATE_HOME"] = os.path.join(t, "state-" + name)
    return path


def back_home():
    mod.HOME = HOME1
    os.environ["HOME"] = HOME1
    os.environ["XDG_STATE_HOME"] = STATE1


def log(name):
    try:
        return open(os.path.join(t, name), encoding="utf-8").read()
    except OSError:
        return ""


def reset():
    for name in ("udisks.log", "pill.log", "lsblk.log", "findmnt.log", "mounted", "mountopts", "ro", "busy", "crypt.json"):
        try:
            os.unlink(os.path.join(t, name))
        except OSError:
            pass


def tree(root):
    return sorted(os.path.relpath(os.path.join(d, f), root) for d, _x, files in os.walk(root) for f in files)


ADMIN = {"yes": True}
mod.is_admin = lambda: ADMIN["yes"]
mod.own_names = lambda: {"sam", "sam smith", "samsmith"}
# What the driver says of a file's Windows attributes: one file is a OneDrive placeholder; the rest say nothing, as ntfs3 may not
mod.attributes = lambda path: 0x00400000 if "attr-placeholder" in path else None

# 1. The offer: nothing mounted, no password; every NTFS or BitLocker volume of a size that could be a system, not the recovery and boot stubs,
#    not the volume this system runs from
reset()
code, out, _err = call("find", "--offer")
parts = [p["part"] for p in json.loads(out)["parts"]]
check("offer exit", code == 0, out)
check("offer parts", parts == ["/dev/sda2", "/dev/sdb2", "/dev/sdc1", "/dev/sdd"], str(parts))
check("offer mounts nothing", log("udisks.log") == "", log("udisks.log"))

# 2. find: the Windows disk's accounts, mounted read-only and unmounted again; the locked disk said so; the data disk is no Windows
reset()
code, out, _err = call("find", "--json")
found = {p["part"]: p for p in json.loads(out)["parts"]}
check("find exit", code == 0, out)
check("find windows", found["/dev/sda2"]["windows"] is True and found["/dev/sda2"]["accounts"] == ["Pat", "Sam"], str(found.get("/dev/sda2")))
check("find locked", found["/dev/sdc1"].get("locked") is True and found["/dev/sdc1"]["accounts"] == [], str(found.get("/dev/sdc1")))
check("find leaves the data disks out", "/dev/sdd" not in found and "/dev/sdb2" not in found, str(list(found)))
for line in log("udisks.log").splitlines():
    if line.startswith("mount "):
        check("mounted read-only, no exec", line.endswith("-o ro,noexec,nosuid,nodev"), line)
lines = log("udisks.log").splitlines()
check("every mount is undone", lines and sum(x.startswith("mount ") for x in lines) == sum(x.startswith("unmount ") for x in lines), str(lines))
check("find never touched the locked disk", "sdc1" not in log("udisks.log"), log("udisks.log"))

# 3. A person who is not an administrator sees their own account only, and copies no other
ADMIN["yes"] = False
reset()
code, out, _err = call("find", "--json")
check("non-admin sees only their own", [p["accounts"] for p in json.loads(out)["parts"] if p["part"] == "/dev/sda2"] == [["Sam"]], out)
reset()
code, out, err = call("copy", "/dev/sda2", "Pat", "--yes")
check("non-admin cannot copy another account", code == 1 and "administrator" in err and not os.path.exists(os.path.join(os.environ["HOME"], "Documents", "pat.txt")), err)
ADMIN["yes"] = True

# 4. A device nobody offered is never opened
reset()
code, out, err = call("look", "/dev/sdb1")
check("this system's own volume is refused", code == 1 and log("udisks.log") == "", err)
code, out, err = call("look", "/etc/passwd")
check("a path is refused", code == 1 and log("udisks.log") == "", err)

# 5. look: the folders, what is in them, and the placeholders (the attribute's and the sparse one's)
reset()
code, out, _err = call("look", "/dev/sda2", "--json")
look = {a["name"]: a for a in json.loads(out)["accounts"]}
sam = {f["id"]: f for f in look["Sam"]["folders"]}
check("look folders", sorted(sam) == ["desktop", "documents", "music", "pictures", "videos"], str(sorted(sam)))
check("look documents", sam["documents"]["files"] == 3 and sam["documents"]["placeholders"] == 2, str(sam["documents"]))
check("look music", sam["music"]["bytes"] == 300000, str(sam["music"]))
check("look is Sam's own", look["Sam"]["mine"] is True and look["Pat"]["mine"] is False)

# 6. A disk the desktop mounted read-write: find and look leave it alone and say so; copy says so first, asks, mounts it read-only for the copy,
#    and puts the desktop's mount back; a mount that is busy, and one that is not the desktop's, are left as they are
def desktop_mount(options="rw,nosuid,nodev,relatime", point="/run/media/sam/Windows"):
    with open(os.path.join(t, "mounted"), "w") as handle:
        handle.write(point)
    with open(os.path.join(t, "mountopts"), "w") as handle:
        handle.write(options)


reset()
desktop_mount()
code, out, err = call("look", "/dev/sda2", "--json")
check("look leaves the desktop's mount alone and says so", code == 1 and log("udisks.log") == "" and "left as it is" in err and out == "", err)
reset()
desktop_mount()
code, out, err = call("find", "--json")
listing = {p["part"]: p for p in json.loads(out)["parts"]}
check("find lists it with the reason, and unmounts nothing", "left as it is" in listing["/dev/sda2"].get("error", "") and log("udisks.log") == "", out)
reset()
desktop_mount()
use_home("home6")
code, out, err = call("copy", "/dev/sda2", "Sam", "--folders", "music", "--json")
check("copy without a yes touches nothing", code == 1 and log("udisks.log") == "", err)
reset()
desktop_mount()
code, out, err = call("copy", "/dev/sda2", "Sam", "--folders", "music", "--yes", "--json")
lines = log("udisks.log").splitlines()
check("copy replaces the desktop's mount, and says so first", code == 0 and "mounted as it was" in err and out.strip().startswith("{"), err)
check("the ro mount is made, undone, and the desktop's put back", len(lines) == 4 and lines[0].startswith("unmount") and lines[1].endswith("-o ro,noexec,nosuid,nodev")
      and lines[2].startswith("unmount") and lines[3].startswith("mount -b /dev/sda2") and "-o" not in lines[3], str(lines))
check("copy copied", os.path.exists(os.path.join(mod.HOME, "Music", "song.mp3")))
reset()
desktop_mount()
with open(os.path.join(t, "busy"), "w") as handle:
    handle.write("1")
code, out, err = call("copy", "/dev/sda2", "Sam", "--yes", "--json")
lines = log("udisks.log").splitlines()
check("a busy mount is left as it was, and said", code == 1 and "busy" in err and len(lines) == 1 and lines[0].startswith("unmount"), str(lines) + err)
reset()
desktop_mount("rw,relatime", "/mnt/windows")
code, out, err = call("look", "/dev/sda2")
check("a mount of somebody else's, read-write, is left alone", code == 1 and log("udisks.log") == "", err)
reset()
back_home()

# 7. BitLocker: no terminal, no key; with a key, it is unlocked read-only, the key reaches nothing but the unlock, and the disk is locked again
code, out, err = call("look", "/dev/sdc1")
check("a locked disk asks for a terminal", code == 1 and "recovery key" in err and log("udisks.log") == "", err)
seen = {}
mod.unlock = lambda device, key: (seen.update(device=device, key=key) or ("/dev/dm-0", "/org/freedesktop/UDisks2/block_devices/sdc1"))
mod.lock = lambda path: seen.update(locked=path)
KEY = "123456-234567-345678-456789-567890-678901-789012-890123"
reset()
with mod.Volume("/dev/sdc1", lambda: KEY) as volume:
    check("an unlocked volume is mounted", volume.root == win and "mount -b /dev/dm-0 -o ro,noexec,nosuid,nodev" in log("udisks.log"), log("udisks.log"))
check("the key reached the unlock once", seen.get("key") == KEY and seen.get("device") == "/dev/sdc1")
check("the volume is locked again", seen.get("locked") == "/org/freedesktop/UDisks2/block_devices/sdc1" and "unmount -b /dev/dm-0" in log("udisks.log"))
seen.clear()
reset()
with open(os.path.join(t, "ro"), "w") as handle:
    handle.write("0")
try:
    with mod.Volume("/dev/sdc1", lambda: KEY):
        check("a volume that is not read-only is refused", False)
except mod.Problem:
    check("a volume that is not read-only is refused", "mount -b" not in log("udisks.log") and seen.get("locked"), log("udisks.log"))
reset()
leaked = [d for d, _x, files in os.walk(t) for f in files if f != "driver.py" and KEY in open(os.path.join(d, f), "rb").read().decode("utf-8", "replace")]
check("the key is in no file", not leaked, str(leaked))

# 8. copy: into a home that already has a different report.docx
home = os.environ["HOME"]
os.makedirs(os.path.join(home, "Documents"), exist_ok=True)
with open(os.path.join(home, "Documents", "report.docx"), "w") as handle:
    handle.write("mine, not Windows'")
reset()
code, out, err = call("copy", "/dev/sda2", "Sam", "--json")
done = json.loads(out)
check("copy exit", code == 0, err)
check("a file already here is never replaced", open(os.path.join(home, "Documents", "report.docx")).read() == "mine, not Windows'")
check("the copy is beside it", open(os.path.join(home, "Documents", "report (from Windows).docx")).read().strip() == "the report, Windows' copy", str(tree(home)) + out + err)
check("a folder is copied whole", open(os.path.join(home, "Documents", "letters", "a.txt")).read().strip() == "dear Sam", str(tree(home)))
check("OneDrive's downloaded files come too", os.path.exists(os.path.join(home, "Documents", "synced.txt")) and os.path.exists(os.path.join(home, "Pictures", "there.jpg")))
check("placeholders are skipped", not os.path.exists(os.path.join(home, "Documents", "attr-placeholder.docx")) and not os.path.exists(os.path.join(home, "Documents", "sparse-placeholder.docx")))
check("the counts", done["placeholders"] == 2 and done["beside"] == 1 and done["failed"] == 0 and done["already"] == 0, str(done))
check("music, videos, desktop, pictures arrive", all(os.path.exists(os.path.join(home, *p)) for p in (("Music", "song.mp3"), ("Videos", "v.mp4"), ("Desktop", "todo.txt"), ("Pictures", "p.jpg"))))
everything = tree(home)
check("Downloads is left out", not any("setup.exe" in f for f in everything), str(everything))
check("no browser data, no AppData", not any("AppData" in f or "Login Data" in f for f in everything), str(everything))
check("another account is not copied", not any("pat.txt" in f for f in everything))
check("links and junk are passed over", not any(n in f for f in everything for n in ("hostname-link", "etc-folder", "desktop.ini", "Thumbs.db", "~$")), str(everything))
check("no half file is left", not any(f.endswith(".amethystora-partial") for f in everything), str(everything))
check("modification times are kept", abs(os.stat(os.path.join(home, "Pictures", "p.jpg")).st_mtime - os.stat(os.path.join(win, "Users", "Sam", "Pictures", "p.jpg")).st_mtime) < 2)
check("the volume is unmounted again", log("udisks.log").splitlines()[-1].startswith("unmount"), log("udisks.log"))
canary = [d for d, _x, files in os.walk(home) for f in files if b"CANARY" in open(os.path.join(d, f), "rb").read()]
check("no password is read into the home", not canary, str(canary))
pill = log("pill.log").splitlines()
check("the pill starts, moves and ends", pill and pill[0].startswith("start move-in ") and pill[-1] == "end move-in" and "--pid" in pill[0], str(pill))
check("the pill names no file", not any(n in log("pill.log") for n in ("report", "Sam", "synced")), log("pill.log"))

# 9. Again: nothing copied, nothing beside it twice; and a copy edited since is not copied once more
reset()
with open(os.path.join(home, "Documents", "letters", "a.txt"), "w") as handle:
    handle.write("edited here")
code, out, err = call("copy", "/dev/sda2", "Sam", "--json")
again = json.loads(out)
check("a second run copies nothing", code == 0 and again["copied"] == 0 and again["already"] == done["copied"] and again["beside"] == 0, str(again))
check("what was edited here stays edited", open(os.path.join(home, "Documents", "letters", "a.txt")).read() == "edited here" and tree(home) == everything)

# 10. A run that is stopped, in a home of its own, carries on where it stopped
home2 = os.path.join(t, "home2")
os.makedirs(os.path.join(home2, "Documents"))
mod.HOME = home2
os.environ["HOME"] = home2
os.environ["XDG_STATE_HOME"] = os.path.join(t, "state2")
real_copy = mod.copy_one
count = {"n": 0}


def stops(path, st, final, progress):
    count["n"] += 1
    if count["n"] == 4:
        raise KeyboardInterrupt
    return real_copy(path, st, final, progress)


mod.copy_one = stops
with open(os.path.join(home2, "Documents", ".old.1234.amethystora-partial"), "w") as handle:
    handle.write("half")
reset()
code, out, err = call("copy", "/dev/sda2", "Sam", "--json")
check("a stop is said, and the way on", code == 1 and "Run it again" in err, err)
check("a stop leaves no half file, and takes away an old one", not [f for f in tree(home2) if f.endswith(".amethystora-partial")] and len(tree(home2)) == 3, str(tree(home2)))
mod.copy_one = real_copy
code, out, err = call("copy", "/dev/sda2", "Sam", "--json")
resumed = json.loads(out)
check("the run after a stop copies the rest and not what was across", code == 0 and resumed["already"] == 3 and resumed["copied"] == done["copied"] - 3, str(resumed))
check("both runs make the whole", tree(home2) == [f for f in everything if "(from Windows" not in f], str(tree(home2)))

# 11. Not enough room: said, and nothing is copied
real_usage = mod.shutil.disk_usage
mod.shutil.disk_usage = lambda path: type("U", (), {"free": 1000})()
home3 = os.path.join(t, "home3")
os.makedirs(home3)
mod.HOME = home3
os.environ["HOME"] = home3
os.environ["XDG_STATE_HOME"] = os.path.join(t, "state3")
code, out, err = call("copy", "/dev/sda2", "Sam", "--json")
check("no room is said", code == 1 and "does not fit" in err and not tree(home3), err)
mod.shutil.disk_usage = real_usage

# 12. A folder asked for by id only
home4 = os.path.join(t, "home4")
os.makedirs(home4)
mod.HOME = home4
os.environ["HOME"] = home4
os.environ["XDG_STATE_HOME"] = os.path.join(t, "state4")
code, out, err = call("copy", "/dev/sda2", "Sam", "--folders", "music", "--json")
check("only the folder asked for", code == 0 and tree(home4) == ["Music/song.mp3"], str(tree(home4)))

# 13. The whole thing in a terminal: no terminal, no go; with one, the disk and the account picked by number and each folder answered
code, out, err = call()
check("no terminal, no go", code == 1 and "terminal" in err, err)


class Terminal(io.StringIO):
    def isatty(self):
        return True


home5 = os.path.join(t, "home5")
os.makedirs(home5)
mod.HOME = home5
os.environ["HOME"] = home5
os.environ["XDG_STATE_HOME"] = os.path.join(t, "state5")
real_stdin, real_stdout = sys.stdin, sys.stdout
# Disk 1 (Windows), account 2 (Sam: Pat is first), then Documents yes, Pictures yes, Music no, Videos no, Desktop yes
sys.stdin = Terminal("1\n2\ny\ny\nn\nn\ny\n")
shown = Terminal()
sys.stdout = shown
try:
    code = mod.main(["amethystora-move-in"])
finally:
    sys.stdin, sys.stdout = real_stdin, real_stdout
check("the walk through ends well", code == 0, shown.getvalue())
check("the walk copied what was said yes to", tree(home5) == ["Desktop/todo.txt", "Documents/letters/a.txt", "Documents/report.docx", "Documents/synced.txt", "Pictures/p.jpg", "Pictures/there.jpg"], str(tree(home5)))
check("the walk offered Downloads to nobody and said what OneDrive kept", "Downloads" not in shown.getvalue() and "only in OneDrive" in shown.getvalue(), shown.getvalue())
check("the walk's disk is unmounted again", not os.path.exists(os.path.join(t, "mounted")))

# 13b. A link planted at a temporary file's name is not followed (the old name was .NAME.PID.amethystora-partial); a link in the home that leads out of
#      it is not written through; a file where a folder is needed is one counted clash; names of any length and script; deep trees; accounts by real name
home7 = use_home("home7")
os.makedirs(os.path.join(home7, "Documents"))
with open(os.path.join(home7, "victim"), "w") as handle:
    handle.write("precious")
for planted in (f".report.docx.{os.getpid()}.amethystora-partial", ".guess.amethystora-partial"):
    os.symlink(os.path.join(home7, "victim"), os.path.join(home7, "Documents", planted))
code, out, err = call("copy", "/dev/sda2", "Sam", "--folders", "documents", "--yes", "--json")
check("a planted link is not written through", code == 0 and open(os.path.join(home7, "victim")).read() == "precious" and json.loads(out)["failed"] == 0, out + err)
check("the planted links are swept as links", not [f for f in os.listdir(os.path.join(home7, "Documents")) if f.endswith(".amethystora-partial")])
check("and the copy was made", os.path.exists(os.path.join(home7, "Documents", "letters", "a.txt")))

# ...and, were one planted at the very name that is used (the sweep and the token put out of the way), nothing is written through it
home7b = use_home("home7b")
os.makedirs(os.path.join(home7b, "Documents"))
with open(os.path.join(home7b, "victim"), "w") as handle:
    handle.write("precious")
os.symlink(os.path.join(home7b, "victim"), os.path.join(home7b, "Documents", ".deadbeefdeadbeef.amethystora-partial"))
real_sweep, real_token = mod.sweep_partials, mod.secrets.token_hex
mod.sweep_partials = lambda folder: None
mod.secrets.token_hex = lambda size: "deadbeefdeadbeef"
code, out, err = call("copy", "/dev/sda2", "Sam", "--folders", "documents", "--yes", "--json")
mod.sweep_partials, mod.secrets.token_hex = real_sweep, real_token
check("a link at the very name of the temporary file is not written through", open(os.path.join(home7b, "victim")).read() == "precious" and json.loads(out)["failed"] >= 1, out + err)

home8 = use_home("home8")
outside = os.path.join(t, "outside8")
os.makedirs(outside)
os.makedirs(os.path.join(home8, "Documents"))
os.symlink(outside, os.path.join(home8, "Documents", "letters"))
code, out, err = call("copy", "/dev/sda2", "Sam", "--folders", "documents", "--yes")
check("a link out of the home is not written through", code == 0 and os.listdir(outside) == [], str(os.listdir(outside)) + out + err)
check("it is counted, with its own sentence, and the rest is copied", "lead out of your home" in out and os.path.exists(os.path.join(home8, "Documents", "synced.txt")), out)

home9 = use_home("home9")
os.makedirs(os.path.join(home9, "Documents"))
with open(os.path.join(home9, "Documents", "letters"), "w") as handle:
    handle.write("a file, not a folder")
code, out, err = call("copy", "/dev/sda2", "Sam", "--folders", "documents", "--yes", "--json")
counted = json.loads(out)
check("a file where a folder is needed is one clash, not a failure for each file", counted["clash"] == 1 and counted["failed"] == 0, out)
check("and what was there is untouched", open(os.path.join(home9, "Documents", "letters")).read() == "a file, not a folder" and os.path.exists(os.path.join(home9, "Documents", "synced.txt")))
code, out, err = call("copy", "/dev/sda2", "Sam", "--folders", "documents", "--yes")
check("the clash has its sentence", "have the name of a file you have here" in out, out)

# Accounts whose folder names are cut or cleaned to be shown, and a name of eighty characters of three bytes
users = os.path.join(win, "Users")
long_name = "L" * 70
bidi_name = "Zo\u202eE"
for name, wrote in ((long_name, "long.txt"), (bidi_name, "bidi.txt")):
    os.makedirs(os.path.join(users, name, "Documents"))
    open(os.path.join(users, name, "NTUSER.DAT"), "w").close()
    with open(os.path.join(users, name, "Documents", wrote), "w") as handle:
        handle.write(wrote)
cjk = "\u6587" * 80 + ".txt"
with open(os.path.join(users, "Pat", "Documents", cjk), "w") as handle:
    handle.write("a long name")
code, out, err = call("look", "/dev/sda2", "--json")
names = [a["name"] for a in json.loads(out)["accounts"]]
check("a long name is cut and a bidi mark taken out to be shown", "L" * 60 in names and "ZoE" in names and long_name not in names, str(names))
home10 = use_home("home10")
code, out, err = call("copy", "/dev/sda2", "L" * 60, "--yes", "--json")
check("an account shown cut is copied by its real name", code == 0 and json.loads(out)["copied"] == 1 and os.path.exists(os.path.join(home10, "Documents", "long.txt")), out + err)
code, out, err = call("copy", "/dev/sda2", "ZoE", "--yes", "--json")
check("an account shown cleaned is copied by its real name", code == 0 and json.loads(out)["copied"] == 1 and os.path.exists(os.path.join(home10, "Documents", "bidi.txt")), out + err)
code, out, err = call("copy", "/dev/sda2", long_name, "--yes", "--json")
check("or by the real name itself, and then it is all already across", code == 0 and json.loads(out)["already"] == 1, out + err)
code, out, err = call("copy", "/dev/sda2", "Nobody", "--yes", "--json")
check("an account that is not there is refused", code == 1)
home11 = use_home("home11")
code, out, err = call("copy", "/dev/sda2", "Pat", "--yes", "--json")
check("a name of eighty characters of three bytes is copied", code == 0 and json.loads(out)["failed"] == 0 and os.path.exists(os.path.join(home11, "Documents", cjk)), out + err)
for name in (long_name, bidi_name):
    shutil.rmtree(os.path.join(users, name))
os.unlink(os.path.join(users, "Pat", "Documents", cjk))

# A tree of folders deeper than Python's recursion limit
deep_dir = os.path.join(users, "Deep", "Documents")
os.makedirs(deep_dir)
open(os.path.join(users, "Deep", "NTUSER.DAT"), "w").close()
descriptor = os.open(deep_dir, os.O_RDONLY)
for _level in range(1200):
    os.mkdir("a", dir_fd=descriptor)
    deeper = os.open("a", os.O_RDONLY, dir_fd=descriptor)
    os.close(descriptor)
    descriptor = deeper
bottom = os.open("deep.txt", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=descriptor)
os.write(bottom, b"deep")
os.close(bottom)
os.close(descriptor)
home12 = use_home("home12")
try:
    code, out, err = call("copy", "/dev/sda2", "Deep", "--yes", "--json")
    reached = os.path.exists(os.path.join(home12, "Documents", *(["a"] * 1200), "deep.txt"))
    check("a tree 1200 folders deep is copied, with no traceback", code == 0 and json.loads(out)["copied"] == 1 and reached, out + err[-300:])
except RecursionError:
    check("a tree 1200 folders deep is copied, with no traceback", False, "RecursionError")
subprocess.run(["rm", "-rf", os.path.join(users, "Deep"), home12], check=False)
back_home()

# A BitLocker volume that is open already is used when it is read-only, and not locked by us; when it is not, the sentence says to lock it
reset()
with open(os.path.join(t, "crypt.json"), "w") as handle:
    handle.write('{"blockdevices":[{"path":"/dev/sdc1","type":"part","children":[{"path":"/dev/dm-9","type":"crypt"}]}]}')
seen.clear()
with mod.Volume("/dev/sdc1", None) as volume:
    check("an open volume is used with no key asked", volume.root == win and "mount -b /dev/dm-9 -o ro,noexec,nosuid,nodev" in log("udisks.log") and not seen, log("udisks.log"))
check("an open volume is not locked by us", "locked" not in seen)
reset()
with open(os.path.join(t, "crypt.json"), "w") as handle:
    handle.write('{"blockdevices":[{"path":"/dev/sdc1","type":"part","children":[{"path":"/dev/dm-9","type":"crypt"}]}]}')
with open(os.path.join(t, "ro"), "w") as handle:
    handle.write("0")
try:
    with mod.Volume("/dev/sdc1", None):
        check("an open volume that is not read-only is refused", False)
except mod.Problem as problem:
    check("an open volume that is not read-only is refused, and says to lock it", "Lock it first" in str(problem) and "mount -b" not in log("udisks.log"), str(problem))
reset()


# 14. What the code does, not what its notes say: nothing that writes to a Windows disk, no way to mount it but read-only, no key but the unlock's
import ast, re
source = open(helper, encoding="utf-8").read()
module = ast.parse(source)
for node in ast.walk(module):
    if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)) and ast.get_docstring(node):
        node.body = node.body[1:] or [ast.Pass()]
code = ast.unparse(module)
for word in ("ntfsfix", "ntfs-3g", "ntfs3", "ntfscp", "ntfsresize", "chntfs", "hiberfile", "cryptsetup", "force", "AppData", "Login Data", "logins.json", "Cookies"):
    check("the code never names " + word, word not in code)
check("a disk is mounted read-only with no exec", code.count("ro,noexec,nosuid,nodev") == 1 and "'rw'" not in code and "defaults" not in code)
check("one place mounts", len(re.findall(r"udisks\(\['mount'", code)) == 1, str(re.findall(r"udisks.{0,20}", code)))
names = sorted(set(re.findall(r"environ(?:\.get)?[\[(]'(\w+)'", code)))
check("the environment is read for the state and runtime folders only", names == ["XDG_RUNTIME_DIR", "XDG_STATE_HOME"], str(names))
check("the temporary file is made exclusively, with no link followed", "O_EXCL" in code and code.count("O_NOFOLLOW") >= 3)
check("the recovery key comes from no argument", "--key" not in code and code.count("argv") == 3)

print(f"test-move-in: {len(asked)} checks, {len(failures)} failed")
sys.exit(1 if failures else 0)
PY
python3 -I "${T}/driver.py" "${HELPER}" "${T}" "${WIN}" || fail "the helper's checks failed (above)"
[[ "$(disk_sum)" == "$(cat "${T}/win.sum")" ]] || fail "the Windows disk's files changed"

bash -n "$0" || fail "this script does not parse"
echo "test-move-in: ok"
