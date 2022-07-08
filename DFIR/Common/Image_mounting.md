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

###### Expert Witness/EnCase (EWF) image

The following procedure can be following to mount disk images in the
`Expert Witness/EnCase (EWF)` format:

```bash
# Mount the raw EWF image. Following the ewfmount, an "ewf1" file should be present in the <RAW_EWF_DIR_PATH> directory.
# The ewfmount utility is part of the "ewf-tools" package on Debian / Kali Linux.
mkdir <RAW_EWF_DIR>
ewfmount <EWF_FILE_PATH> <RAW_EWF_DIR_PATH>

# Mount the image as a loop device.
# show_sys_files and streams_interace=windows are options for Windows NTFS partitions.
mkdir <MOUNTPOINT>
mount <RAW_EWF_DIR_PATH>/ewf1 <MOUNTPOINT_PATH> -o ro,loop,noatime,noexec,noload[,show_sys_files,streams_interace=windows]
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
# show_sys_files and streams_interace=windows are options for Windows NTFS partitions.

# OFFSET = SECTOR_SIZE * PARTITION_START.

sudo mount -o ro,noload,noatime,noexec,[show_sys_files,streams_interace=windows,]offset=<OFFSET | $((<SECTOR_SIZE> * <PARTITION_START>))> <IMAGE_FILE> </mnt/ | MOUNT_POINT>
```
