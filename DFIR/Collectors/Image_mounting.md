# DFIR - Image mounting

Following the imaging of a system disk, the image taken must be mounted as a
partition for analysis. Numerous tools can be used, from either the Windows or
Linux operating systems, to do so. An important aspect of image mounting is the
preservation of the artefacts integrity. The image should be mounted in
read-only (or temporary write), with a few specificities to preserve timestamps
and data integrity.

Some utilities, such as `Autoruns`, require writable partitions. To use such
utilities, the image should be mounted using an utility supporting temporary
writes.

### From Windows

The [`Arsenal Image Mounter`](https://arsenalrecon.com/downloads/) is a
powerful graphical utility that can be used to mount multiple image types. It
supports temporary write using a diff file that will store the modifications.
`Arsenal Image Mounter` will automatically mount the different partitions of
a given image and implements decryption of `BitLocker` protected partition.

`Arsenal Image Mounter` supports the following disk image format:
  - `raw` / `DD`
  - Multi-parts `raw`
  - `EnCase Evidence File (E01)`
  - `Advanced Forensics Format (AFF)`
  - `VDI` / `VMDK` / `VHD`

Other utilities such as `FTK Imager` or `OSF Mount` may be used as well.

### From Linux

###### VMDK image

The `guestmount` utility can be used to mount a `VMDK` image directly:

```bash
guestmount -a <VMDK_FILE> -m </dev/sda1 | DEVICE> --ro </mnt/mounted_vmdk | MOUNT_POINT>
```

###### Other image types

The image partitions can be first determined using the `TSK`'s `mmls` or
`fdisk` utilities. The utilities will retrieve the image sector size and the
partition(s) offsets, both required to mount the partition.

```bash
mmls [ -o offset ] <IMAGE_FILE>
fdisk -l <IMAGE_FILE>

# Units are in <SECTOR_SIZE>-byte sectors
# Slot      Start             End   Length  Description
# [...]
# 02: 00:00 <PARTITION_START> XXX   YYY     NTFS
```

```bash
# mount options:
# ro : read-only.
# noatime : preserve the atime (last access time) timestamps.
# noexec : files from the mounted partition cannot be executed.
# noload : prevent replaying of the partition journal to preserve integrity.
# loop : explicitly tells mount to use a loop device (optional on newer version of mount).

# OFFSET = SECTOR_SIZE * PARTITION_START.

sudo mount -o ro,noload,noatime,noexec,offset=<OFFSET> <IMAGE_FILE> </mnt/ | MOUNT_POINT>
```
