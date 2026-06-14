> [!IMPORTANT]
> If `aa-status` returns `apparmor filesystem is not mounted.`, add the following line to `GRUB_CMDLINE_LINUX` in `/etc/default/grub`:
> ```
> lsm=landlock,lockdown,yama,integrity,apparmor,bpf
> ```
> Then run `sudo grub-mkconfig -o /boot/grub/grub.cfg` and reboot.
>
> If you still see the same message after this, you most likely installed Arch using `archinstall >= 2.7`, which added Unified Kernel Image (UKI) support
> (https://www.phoronix.com/news/Arch-Linux-Archinstall-2.7). With this setup, GRUB is **not** what passes kernel parameters -- the cmdline is baked directly into the UKI at build time. Editing `/etc/default/grub` has no effect. Follow the steps below instead.

### Fix for UKI-based installs

1. **Edit the cmdline used by the UKI directly:**

```bash
sudo nano /etc/kernel/cmdline
```

Add the AppArmor parameters to the existing line, e.g.:

```
root=PARTUUID=YOUR_ROOT_PARTUUID zswap.enabled=0 rw rootfstype=ext4 apparmor=1 security=apparmor lsm=landlock,lockdown,yama,integrity,apparmor,bpf
```

2. **Rebuild the UKI:**

```bash
sudo mkinitcpio -P
```

This regenerates `/boot/EFI/Linux/arch-linux.efi` with the new cmdline embedded. Reboot and confirm:

```bash
cat /proc/cmdline   # should show your apparmor params
sudo aa-status      # should report module loaded
```

3. **Register a dedicated UEFI boot entry for the UKI** (so kernel/initramfs updates -- which `pacman` automatically rebuilds via `mkinitcpio -P` -- are always picked up without any manual file copying):

```bash
# Find your ESP disk and partition number
lsblk -f

# Example output:
# nvme0n1
# ├─nvme0n1p1 vfat   FAT32       XXXX-XXXX   291.7M  71%  /boot
# └─nvme0n1p2 ext4   1.0         XXXXXX      712.9G  17%  /

sudo efibootmgr --create --disk /dev/nvme0n1 --part 1 \
  --label "Arch Linux" \
  --loader '\EFI\Linux\arch-linux.efi'

# Verify and note the new entry's number (e.g. 0000)
sudo efibootmgr -v
```

4. **Restore GRUB as the boot menu** (if `archinstall` already set up GRUB but it's no longer registered or was overwritten):

```bash
sudo grub-install --target=x86_64-efi --efi-directory=/boot --bootloader-id=GRUB
sudo grub-mkconfig -o /boot/grub/grub.cfg
```

> [!NOTE]
> Modern GRUB ships `/etc/grub.d/15_uki`, which **automatically detects UKIs in `/EFI/Linux/` and adds a menu entry for them at boot time** -- you do not need (and should not add) a custom `40_custom` menuentry that chainloads the UKI manually, as this will create a duplicate entry in the boot menu.

5. **Set the boot order** so GRUB loads first (showing the menu), with the direct-UKI entry as a fallback:

```bash
sudo efibootmgr -v
# Example result:
# Boot0000* Arch Linux   -> \EFI\Linux\arch-linux.efi   (direct UKI, no menu)
# Boot0001* GRUB         -> \EFI\GRUB\grubx64.efi       (menu, auto-detects UKI)
# Boot0002* UEFI OS      -> \EFI\BOOT\BOOTX64.EFI

sudo efibootmgr -o 0001,0000,0002
```

6. **Set GRUB's default entry** to match the auto-generated UKI entry's title (check the exact title shown in the boot menu first -- it's usually `Arch Linux`):

```bash
sudo sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT="Arch Linux"/' /etc/default/grub
sudo grub-mkconfig -o /boot/grub/grub.cfg
```

7. **Reboot and verify everything:**

```bash
cat /proc/cmdline   # apparmor params should be present
sudo aa-status      # apparmor module should be loaded
```

You should now see the GRUB menu (5-second timeout) with "Arch Linux" as the default, which chainloads into the UKI with AppArmor enabled. Future kernel updates will automatically rebuild `/boot/EFI/Linux/arch-linux.efi` via `mkinitcpio -P` (triggered by a pacman hook), and both the GRUB entry and the direct efibootmgr entry will always point at the up-to-date file -- no manual copying required.