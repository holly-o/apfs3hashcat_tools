# apfs3hashcat_tools
Improvements to apfs2hashcat for extracting APFS hashes


1. Build and run apfs2hashcat tool:

`cd apfs2hashcat`
`mkdir build && cd build`
`cmake ..`
`make`
`sudo ./apfs-dump-quick <image_file_path> ~/Desktop/log.txt /mnt/apfs ~/Desktop/out.json`

NOTE: make sure mount point does not already exist and remember sudo else won't be able to mount the drive

If a fusion drive:
`sudo ./apfs-dump-quick -f <main_drive_file_path> <fusion_drive_file_path> ~/Desktop/log.txt /mnt/apfs ~/Desktop/out.json`
where main_drive = SSD, fusion_drive = HDD


2. Make working directory:

`mkdir /tmp/apfs`
`sudo cp -r /mnt/apfs /tmp`
`sudo chmod 755 /tmp/apfs`

Now you can browse the files in the root directory by navigating to /tmp/apfs


3. Run magic key script:

This should give you information about the user such as full and short usernames, password hint and icon photo.

`python3 magic_key.py -i <location_to_store_icon_photo> -r /tmp/apfs -j ~/Desktop/out.json`

Required python modules:
- PIL (python3 -m pip install Pillow)
