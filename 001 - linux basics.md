# linux basics

## resize kali linux patrition

step 1: shutdown vm, delete snapshots
step 2: resize hdd in vmware settings (host)
step 3: boot into kali, run `sudo fsdisk -l` or `df -h` to identify/verify hdd inquestion
step 4: run `sudo gparted`
step 5: right click linuxswap, deactivate it (swapoff) and move it to the end of the unused diskspace
step 6: resice the hdd in question
step 7: reactivate linux swap (swapon)
step 8: click the checkmark to apply
step 9: verufy with `df -u`

## sharing clipboard

- activate in vmware settings,
- inside kali, run `apt install -y --reinstall open-vm-tools-desktop fuse`

## sharing folders w/ vmware fusion and kali

- create `<folder>` to share
- activate and add in vmware settings
- navigate to `/mnt/hgfs/<folder>`

## the linux filesystem explained (german)

- https://jankarres.de/2014/01/debian-linux-verzeichnisbaum-erklaert/

