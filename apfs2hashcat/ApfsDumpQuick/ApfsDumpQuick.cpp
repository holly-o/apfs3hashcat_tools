/*
	This file is part of apfs-fuse, a read-only implementation of APFS
	(Apple File System) for FUSE.
	Copyright (C) 2017 Simon Gander

	Apfs-fuse is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 2 of the License, or
	(at your option) any later version.

	Apfs-fuse is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with apfs-fuse.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <memory>
#include <cstring>
#include <iostream>
#include <fstream>
#include <map>
#include <sstream>
#include <algorithm>
#include <iostream>

#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

#include <ApfsLib/Device.h>
#include <ApfsLib/ApfsContainer.h>
#include <ApfsLib/ApfsVolume.h>
#include <ApfsLib/BlockDumper.h>
#include <ApfsLib/ApfsDir.h>
#include <ApfsLib/GptPartitionMap.h>
#include <ApfsLib/Util.h>

#include "ApfsLib/Sha256.h"

struct kek_blob_info_t 
{
	kek_blob_t kek_blob;
	int type;
	std::vector<int> featured_volumes;
	size_t order_encountered;
};

struct sha256_hash_t
{
	uint8_t buffer[32];
};

struct apfs_uuid_wrapper_t
{
	apfs_uuid_t uuid;
};

struct seen_earlier
{
	inline bool operator() (const kek_blob_info_t& x, const kek_blob_info_t& y)
	{
		return (x.order_encountered < y.order_encountered);
	}
};

bool operator <(const sha256_hash_t& x, const sha256_hash_t& y) {
	return memcmp(&x, &y, sizeof(sha256_hash_t)) < 0;
}

#define KEK_BLOB_TYPE_AES256 2
#define KEK_BLOB_TYPE_AES128 1
#define DEFAULT_RECOVERY_GUID_HEX_UPPER "EC1C2AD9B6184ED6BD8D50F361C27507"

#define FORK_OFF_AND_AWAIT(code)	\
{						\
	int pid = fork();	\
	if (pid == -1)		\
	{					\
		std::cerr << "Fork failed\n";	\
		return -1;		\
	}					\
	if (pid == 0)		\
	code				\
	waitpid(pid, NULL, 0);	\
}

int parse_args(std::unique_ptr<Device> &main_disk, std::unique_ptr<Device> &tier2_disk, std::ofstream &st, std::string &tmp_mount_point, std::string& json_output, bool& prompt_for_passwords, int argc, char *argv[])
{
	const char *main_name;
	const char *tier2_name;
	const char *output_name;

	int arg_i;

	prompt_for_passwords = false;
	if (argc < 5)
	{
		std::cerr << "Too few arguments provided altogether" << std::endl;
		std::cerr << "Syntax: apfs-dump-quick [-f fusion-secondary-device] <main-device> <Logfile.txt> <tmp-mount-point> <json-output> [-p]" << std::endl;
		return -1;
	}

	arg_i = 1;
	if (!strcmp(argv[1], "-f"))
	{
		if (argc < 7)
		{
			std::cerr << "Too few arguments provided following " << argv[2] << std::endl << std::endl;
			std::cerr << "Syntax: apfs-dump-quick [-f fusion-secondary-device] <main-device> <Logfile.txt> <tmp-mount-point> <json-output> [-p]" << std::endl;
			return -1;
		}

		tier2_name = argv[2];
		std::cout << "Fusion device = " << tier2_name << std::endl;
		arg_i += 2;
	}
	else
	{
		std::cout << "No fusion device provided" << std::endl;
		tier2_name = nullptr;
	}

	// Positional arguments - guaranteed to be present from earlier argument length checks
	main_name = argv[arg_i++];
	output_name = argv[arg_i++];
	tmp_mount_point = std::string(argv[arg_i++]);
	json_output = std::string(argv[arg_i++]);

	std::cout << "Main device = " << main_name << std::endl;

	if (argc > arg_i)
	{
		if (strcmp(argv[arg_i], "-p"))
		{
			std::cerr << "Syntax: apfs-dump-quick [-f fusion-secondary-device] <main-device> <Logfile.txt> <tmp-mount-point> <json-output> [-p]" << std::endl;
			return -1;
		}

		prompt_for_passwords = true;
		arg_i += 1;
	}

	if (argc > arg_i)
	{
		std::cerr << "Too many arguments provided" << std::endl << std::endl;
		std::cerr << "Syntax: apfs-dump-quick <main-device> [-f fusion-secondary-device] <Logfile.txt> <json-output> [-p]" << std::endl;
		return -1;
	}

	if (prompt_for_passwords)
	{
		std::cout << "-p option received. You will be prompted to provide a single password guess for each encrypted volume" << std::endl;
	} else {
		std::cout << "-p option not provided. No effort will be made to decrypt encrypted volumes.. we'll leave that to hashcat >:)" << std::endl;
	}
	std::cout << std::endl;


	// Open stuff
	main_disk.reset(Device::OpenDevice(main_name));
	if (tier2_name)
		tier2_disk.reset(Device::OpenDevice(tier2_name));

	if (!main_disk)
	{
		std::cerr << "Unable to open device " << main_name << std::endl;
		return -1;
	}

	if (tier2_name && !tier2_disk)
	{
		std::cerr << "Unable to open secondary device " << tier2_name << std::endl;
		return -1;
	}

	st.open(output_name);

	if (!st.is_open())
	{
		std::cerr << "Unable to open output file " << output_name << std::endl;
		      main_disk->Close();
		return -1;
	}


	return 0;
}

std::unique_ptr<ApfsContainer> getApfsContainer(std::unique_ptr<Device> &main_disk, std::unique_ptr<Device> &tier2_disk)
{
	uint64_t main_offset;
	uint64_t tier2_offset;
	uint64_t main_size;
	uint64_t tier2_size;

	main_offset = 0;
	main_size = main_disk->GetSize();

	tier2_offset = 0;
	tier2_size = (tier2_disk) ? tier2_disk->GetSize() : 0;


	GptPartitionMap gpt;
	int n;
	if (gpt.LoadAndVerify(*main_disk.get()))
	{
		std::cout << "Info: Found valid GPT partition table on main device. Dumping first APFS partition." << std::endl;

		n = gpt.FindFirstAPFSPartition();
		if (n != -1)
			gpt.GetPartitionOffsetAndSize(n, main_offset, main_size);
	}

	if (tier2_disk && gpt.LoadAndVerify(*tier2_disk.get()))
	{
		std::cout << "Info: Found valid GPT partition table on tier2 device. Dumping first APFS partition." << std::endl;

		n = gpt.FindFirstAPFSPartition();
		if (n != -1)
			gpt.GetPartitionOffsetAndSize(n, tier2_offset, tier2_size);
	}

	std::unique_ptr<ApfsContainer> container(new ApfsContainer(main_disk.get(), main_offset, main_size, tier2_disk.get(), tier2_offset, tier2_size));
	return container;
}

void processKekBlob(kek_blob_t &kek_blob, std::map<sha256_hash_t, kek_blob_info_t> &uniq_kek_blobs, int volume_id)
{
	SHA256 sha256;
	int type = -1;

	switch (kek_blob.unk_82.unk_00)
	{
	case 0x00:
	case 0x10:
		type = KEK_BLOB_TYPE_AES256;
		break;
	case 0x02:
		type = KEK_BLOB_TYPE_AES128;
		break;
	default:
		type = -1;
		std::cerr << "Unknown KEK key flags 82/00 = " << std::hex << kek_blob.unk_82.unk_00 << ". Please work out what is wrong and fix it in a fork of this code :)" << std::endl;
		break;
	}

	if (type < 0)
		return;

	if (type == KEK_BLOB_TYPE_AES128)
	{
		// Check & enforce 0x10 padding on the wrapped kek
		uint32_t(*padding)[4] = (uint32_t (*)[4])(&kek_blob.wrapped_kek[0x18]);
		uint32_t bits = 0;
		for (int i = 0; i < 4; i++)
		{
			bits |= (*padding)[i];
			(*padding)[i] = 0;
		}
		if (bits != 0)
		{
			std::cout << "[!] Warning - wrapped kek of type 1 (AES128) is size 0x18, but wasn't padded with 0x10 zero bytes." << std::endl;
		}
	}

	// Hash the entire kek_blob to uniquely identify it for certain (we don't trust the uuid)
	sha256.Init();
	sha256.Update(&kek_blob, sizeof(kek_blob_t));
	sha256_hash_t digest;
	sha256.Final(digest.buffer);
	
	// Add it to the uniq_kek_blobs map if it's not already there
	// Regardless, add our volume uuid to the vector of featured volumes
	auto search = uniq_kek_blobs.find(digest);
	if (search == uniq_kek_blobs.end())
	{
		std::vector<int> featured_volumes;
		featured_volumes.push_back(volume_id);
		uniq_kek_blobs[digest] = {kek_blob, type, featured_volumes, uniq_kek_blobs.size()};
	} else {
		search->second.featured_volumes.push_back(volume_id);
	}
}

void processVolumes(std::map<sha256_hash_t, kek_blob_info_t> &uniq_kek_blobs, std::vector<std::pair<std::string, apfs_uuid_wrapper_t>> &volume_names, std::unique_ptr<ApfsContainer> &container, std::ofstream &st, bool prompt_for_passwords)
{
	std::string pwd_hint;
	int init_rc;
	ApfsVolume *vol;

	BlockDumper bd(st, container->GetBlocksize());
	container->dump(bd);

	int volumes_cnt = container->GetVolumeCnt();
	volume_names.resize(volumes_cnt);

	// Loop over all the volumes
	for (int volume_id = 0; volume_id < volumes_cnt; volume_id++)
	{

		// GetVolume returns the volume even if it can't complete the init now
		// Setting the password to be blank means than unless prompt_for_passwords is set, it won't call GetVolumeKey on the underlying KeyManager
		vol = container->GetVolume(volume_id, init_rc, std::string(), prompt_for_passwords);

		if (!vol)		// Volume never created (Init never called)
			continue;	

		// Store the volume name & uuid
		const apfs_uuid_t &vol_uuid = vol->uuid();
		volume_names[volume_id] = make_pair(std::string(vol->name()), *(apfs_uuid_wrapper_t*)vol_uuid);
		std::cout << std::endl << "Volume " << volume_id << ": " << vol->name() << std::endl;
		std::cout << "  Volume UUID = " << hexstr(vol_uuid, sizeof(apfs_uuid_t)) << std::endl;

	
		// Leave if Init failed before testing encryption
		if (init_rc < 0 && init_rc >= -4)
		{
			delete vol;
			continue;
		}		

		// Removed the IsEncrypted() condition because it can still find the kek blobs if fails the condition
		// This is assuming kek blobs are only there if there is a password

		// Process all the kekblobs, adding unique ones to the map, and always noting our volume_id against each keyblob
		std::vector<kek_blob_t> kekBlobs = container->GetVolumeKekBlobs(vol_uuid);
		std::cout << "  " << kekBlobs.size() << " kek blobs found" << std::endl;

		for (kek_blob_t kek_blob : kekBlobs)
		{
			processKekBlob(kek_blob, uniq_kek_blobs, volume_id);
		}


		// Remove this because it sometimes gets stuck
		// We can still mount the volumes to look at plist files etc.

		// vol->dump(bd);		// Takes a while if you get the password right, but not forever
		
		delete vol;
	}

	container.reset();
	st.close();
}

void outputHashes(const std::map<sha256_hash_t, kek_blob_info_t> &uniq_kek_blobs, const std::vector<std::pair<std::string, apfs_uuid_wrapper_t>> &volume_names, std::string json_output_fp)
{
	std::cout << uniq_kek_blobs.size() << " uniq kek blobs in total:" << std::endl;

	// Sort the blobs into the order we found them
	std::vector<kek_blob_info_t> uniq_kek_blob_infos;
	for (auto &item : uniq_kek_blobs)
	{
		uniq_kek_blob_infos.push_back(item.second);
	}
	std::sort(uniq_kek_blob_infos.begin(), uniq_kek_blob_infos.end(), seen_earlier());


	// Open our file for output
	std::ofstream json_fs;
	json_fs.open(json_output_fp);
	json_fs << "{\n";

	// Loop over each unique kek blob..
	bool add_comma = false;
	for (auto &item : uniq_kek_blob_infos)
	{
		if (add_comma)
		{
			json_fs << ",\n";
		}
		add_comma = true;

		// Print the uuid.. and warn about any red flags that make it look like the recovery key
		std::string key_blob_uuid_hex = hexstr(item.kek_blob.uuid, sizeof(item.kek_blob.uuid));
		std::cout << "  Kek blob uuid = " << key_blob_uuid_hex << std::endl;
		json_fs << "  \"" << key_blob_uuid_hex << "\" : {\n";

		int suspicious_score = 0;
		if (!strcmp(key_blob_uuid_hex.c_str(), DEFAULT_RECOVERY_GUID_HEX_UPPER))
		{
			std::cout << "  [!] Recognised guid - probably recovery key hash" << std::endl;
			suspicious_score++;
		}
		if (item.kek_blob.iterations == 100000)
		{
			std::cout << "  [!] Very precise number of iterations - probably recovery key hash" << std::endl;
			suspicious_score++;
		}

		// changed from suspicious_score == 2 so that it matches the terminal output
		json_fs << "    \"suspected_recovery\" : " << ( (suspicious_score > 0) ? "true" : "false" ) << ",\n";

		// Build hashcat hash string using a string stream, as we may well want to store it out to a file or similar at some point
		int wrapped_kek_length = (item.type == KEK_BLOB_TYPE_AES128) ? 0x18 : sizeof(item.kek_blob.wrapped_kek);	// = keysize + 0x8
		int hc_mode = (item.type == KEK_BLOB_TYPE_AES128) ? 16700 : 18300;
		std::stringstream hh_ss;
		hh_ss << "$fvde$" << item.type << "$" << sizeof(item.kek_blob.salt) << "$" << hexstr(item.kek_blob.salt, sizeof(item.kek_blob.salt)) << "$" << item.kek_blob.iterations << "$" << hexstr(item.kek_blob.wrapped_kek, wrapped_kek_length);
		std::string hashcat_hash = hh_ss.str();
		std::cout << "  Hashcat hash (mode " << hc_mode << ") = " << hashcat_hash << std::endl;

		json_fs << "    \"hashcat_hash\" : \"" << hashcat_hash << "\"\n";	// No comma on final one

		// Print out each of the volumes which this hash is featured on
		std::cout << "  Featured on volumes: " << std::endl;
		for (int volume_id : item.featured_volumes)
		{
			std::cout << "    " << volume_id << ": " << " [UUID " << hexstr(volume_names[volume_id].second.uuid, sizeof(apfs_uuid_t)) << "] " << volume_names[volume_id].first << std::endl;
		}
		std::cout << std::endl;

		json_fs << "  }";
	}

	json_fs << "\n}\n";
	json_fs.close();

	std::cout << "[+] Hash details output to json successfully" << std::endl << std::endl;

}

int getPathToApfsFuse(char* executable_path, int max_path_len)
{
	char APFS_FUSE[] = "/apfs-fuse";
	ssize_t path_len = readlink("/proc/self/exe", executable_path, max_path_len);
	if (path_len < 0)
	{
		std::cerr << "Readlink failed to get the current executable\n";
		return -1;
	}
	
	executable_path[path_len] = 0;

	if (executable_path[0] != '/')
	{
		std::cerr << "Full executable path doesn't start with a leading /\n";
		return -1;
	}
	while (executable_path[--path_len] != '/');

	if ((size_t)path_len > (max_path_len - sizeof(APFS_FUSE)))
	{
		std::cerr << "Path to apfs-fuse exceeds 4096 characters\n";
		return -1;
	}

	memcpy(executable_path + path_len, APFS_FUSE, sizeof(APFS_FUSE));
	path_len += sizeof(APFS_FUSE) - 1;
	executable_path[path_len] = 0;

	return 0;
}

int getPrebootVolumeStr(std::vector<std::pair<std::string, apfs_uuid_wrapper_t>> volume_names, char* preboot_vol_str)
{
	// Add the -v [preboot index]
	int preboot_vol_i = 0;
	for (; preboot_vol_i < (int)volume_names.size(); preboot_vol_i++)
	{
		if (strcmp(volume_names[preboot_vol_i].first.c_str(), "Preboot") == 0)
			break;
	}

	if (preboot_vol_i == (int)volume_names.size())
	{
		std::cerr << "Didn't find Preboot partition\n";
		return -1;
	}

	if (preboot_vol_i >= 100)
	{
		std::cerr << "Volume ID shouldn't be 3 digits..\n";
		return -1;
	}
	snprintf(preboot_vol_str, 3, "%i", preboot_vol_i);
	return 0;
}

int call_apfs_fuse(char* executable_path, char * argv[], char * tmp_mount_point, char * preboot_vol_str, bool has_tier2_disk)
{
	char* af_args[8];

	// Slightly disgustingly use the layout of the args to this
	af_args[0] = executable_path;
	int arg_i = 1;
	char * main_name = argv[1];
	if (has_tier2_disk)
	{
		af_args[arg_i++] = argv[1];
		af_args[arg_i++] = argv[2];
		main_name = argv[3];
	}

	af_args[arg_i++] = (char*)"-v";
	af_args[arg_i++] = preboot_vol_str;
	af_args[arg_i++] = main_name;
	af_args[arg_i++] = tmp_mount_point;
	af_args[arg_i++] = NULL;

	std::cout << "[ ] Apfs-fuse command:";
	for (int k = 0; k < (arg_i-1); k++)
	{
		std::cout << " " << af_args[k];
	}
	std::cout << std::endl << std::endl;

	
	FORK_OFF_AND_AWAIT({
		execv(executable_path, af_args);	// doesn't return except on error
		return 0;
	})
	
	return 0;
}

int main(int argc, char *argv[])
{
	std::unique_ptr<Device> main_disk;
	std::unique_ptr<Device> tier2_disk;
	std::ofstream st;
	std::string tmp_mount_point;
	std::string json_output_fp;
	bool prompt_for_passwords;

	std::map<sha256_hash_t, kek_blob_info_t> uniq_kek_blobs;
	std::vector<std::pair<std::string, apfs_uuid_wrapper_t>> volume_names;


	// No longer set global debug - skip the keybag dumping printing mess
	g_debug = 0; //g_debug = 0xFF;

	// Parse arguments & open files
	int parse_rc = parse_args(main_disk, tier2_disk, st, tmp_mount_point, json_output_fp, prompt_for_passwords, argc, argv);
	if (parse_rc != 0)
		return parse_rc;

	// Get the APFS container
	std::unique_ptr<ApfsContainer> container = getApfsContainer(main_disk, tier2_disk);

	if (!container->Init())
	{
		std::cerr << "Unable to init container." << std::endl;
		return -1;
	}

	std::cout << std::endl << "================================================================" << std::endl;



	processVolumes(uniq_kek_blobs, volume_names, container, st, prompt_for_passwords);

	std::cout << std::endl << "================================================================" << std::endl << std::endl;

	outputHashes(uniq_kek_blobs, volume_names, json_output_fp);

	// Now we try and fetch the hints from Preboot
	// This will still be quite hacky as we'll use exec to call Apfsfuse and then access the files mounted there
	// We'll try to unmount it

	char executable_path[0x1000];
	if (getPathToApfsFuse(executable_path, sizeof(executable_path)) < 0)
		return -1;

	char preboot_vol_str[3];
	if (getPrebootVolumeStr(volume_names, preboot_vol_str) < 0)
		return -1;

	std::cout << "[ ] Unmounting provided tmp mount point (if present)" << std::endl;
	FORK_OFF_AND_AWAIT({
		execl("/usr/bin/umount", "/usr/bin/umount", tmp_mount_point.c_str(), NULL);
		return 0;
	})
	
	std::cout << "[ ] Creating directory for mount point (if not present already)" << std::endl;
	FORK_OFF_AND_AWAIT({
		execl("/usr/bin/mkdir", "/usr/bin/mkdir", tmp_mount_point.c_str(), NULL);
		return 0;
	})

	call_apfs_fuse(executable_path, argv, (char*)tmp_mount_point.c_str(), preboot_vol_str, (bool)tier2_disk);
	std::cout << std::endl << "[+] apfs-fuse call finished" << std::endl;

}