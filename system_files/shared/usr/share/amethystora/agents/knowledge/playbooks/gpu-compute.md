# CUDA, ROCm or the render node does not work in a container

## Symptom
`podman run` with a graphics card fails ("unresolvable CDI devices", no `/dev/kfd`, `nvidia-smi` or `rocminfo` finds
nothing in the container), or the person asks whether the card can be used for compute.

## Look
- `ame dev gpu --json` (changes nothing, fetches nothing): the first step with `state` `fail` is the cause, its `text` says
  it and its `fix` is the command. `skipped` is a container step that needs an image the machine does not have yet, with
  its size in `text`.
- `state overview` (the flavor and the GPU line), `ame system drivers --json` and `/usr/libexec/amethystora-gpu-check offer`
  are what steps 1 and 2 already read.
- NVIDIA: `nvidia-smi -L` on the host, `nvidia-ctk cdi list` (it must list `nvidia.com/gpu=all`), `ls /run/cdi /etc/cdi`.
- AMD: `ls -l /dev/kfd /dev/dri`. Intel: `ls -l /dev/dri`.

## Causes on Amethystora
1. **The wrong image.** Without NVIDIA's driver nouveau draws on the card, and nothing computes: the NVIDIA playbook's
   cause 4. `ame dev gpu` names the image in step 2.
2. **The driver did not load** (Secure Boot's key not enrolled, lockdown): the NVIDIA playbook's causes 1 to 3.
3. **No CDI description.** The NVIDIA images write `/run/cdi/nvidia.yaml` at every start, through the toolkit's
   `nvidia-cdi-refresh` service and path units, which are skipped while the driver is not loaded. After the driver loads,
   `sudo systemctl start nvidia-cdi-refresh` writes it. If a start leaves it missing with the driver loaded, that is a
   fault of the image: say so (`ame report`).
4. **`/dev/kfd` missing on AMD.** The card is one the amdgpu driver has no compute for, or ROCm does not support it.
   Fedora's own rule gives every account `/dev/kfd` and the render nodes (group `render`, mode 0666), so a missing
   access is a rule the machine's owner added, never a group to join.
5. **SELinux.** podman is given `--security-opt=label=disable` for the check, as NVIDIA documents; a person's own
   `podman run` needs it for NVIDIA devices too.

## Fix
Run the `fix` of the first failed step as the user. A command with `sudo` or `ame system rebase` is the person's
(`run`); `ame dev gpu --pull` and `--deep` are theirs too.

## Verify
`ame dev gpu` ends with "A container can use the card." and exits 0.

## Undo
Nothing was changed by the check. The image `--pull` fetched stays in podman's storage: `podman image rm IMAGE`.
