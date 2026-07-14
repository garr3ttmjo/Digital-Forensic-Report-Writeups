# Linux Forensics Scenario

**Date:** January 29, 2024  
**Author:** Garrett Jones  

Challenge created by Jean Carlos Martins Miguel and available at:

- https://cfreds.nist.gov/all/utfpr/LinuxForensicsScenario
- https://drive.google.com/drive/folders/1_C-YorlEjuiCF6dBPmKhLd2Z7l43Q9YN

## Concepts

- Linux Disk Forensics
- Filesystem Analysis
- Deleted File Recovery
- Steganography
- Encryption and Decryption
- Browser Artifact Analysis

---

# Scenario

A Linux computer was seized during a simulated law enforcement investigation involving the distribution of illegal content. The computer owner admitted to possessing and distributing illicit files.

As a forensic analyst assisting law enforcement, the objective was to examine the acquired disk image, identify relevant artifacts, recover deleted data, analyze user activity, and locate evidence that could support the investigation.

**Note:** This scenario is a forensic training exercise created for educational purposes. No actual illegal content exists within the evidence image. The images considered suspicious in this challenge are simulated files generated from a machine learning dataset.

---

# Investigation

The provided evidence consisted of a raw (`dd`) disk image from an ext4 Linux filesystem.

The filesystem type was identified using `disktype`:

![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/0a7e9632-7797-4d66-b641-85b92d7b9c0c)

---

## Evidence Integrity Verification

Before beginning analysis, the evidence image was hashed to establish a baseline and verify data integrity throughout the investigation.

The calculated hashes were:
```
SHA1: 18a91d4a2182627794a298563a73ce6c65b00065
MD5: e5dc2aec9a7332567654ebf6d8ce8677
```

These values can be used to confirm that the original evidence image was not modified during examination.

---

# Tools Used

The following forensic tools were used during analysis:

| Tool | Purpose |
|---|---|
| FTK Imager | Examine disk image contents without mounting |
| Autopsy | Automated forensic artifact extraction and analysis |
| SIFT Workstation | Mount and analyze Linux filesystem artifacts |
| Steghide | Identify and extract hidden data from images |
| John the Ripper | Password cracking |
| GPG | Decryption of encrypted evidence |
| DB Browser for SQLite | Browser database analysis |

FTK Imager was used for initial examination of the disk image without modifying the evidence source. Autopsy was used to process filesystem artifacts and identify potentially relevant evidence automatically. SIFT Workstation was used to mount and interact with the Linux filesystem directly.

---

# Important Linux Artifacts

Linux systems contain several artifacts that are commonly examined during forensic investigations. These locations can provide valuable information about user activity, system configuration, authentication events, and potential evidence.

The following artifacts were reviewed during analysis:

- Bash history
- Network configuration files
- Authentication logs
- User account files
- Browser history databases
- Deleted file locations
- Encryption keys and encrypted files

---

# Bash History

The Bash history file contains commands previously executed by the user.

Analysis of the user's Bash history revealed several important commands, including:

- Hashing multiple image files using `sha1sum`
- References to steganography using Steghide
- References to encrypted files using GPG

These commands provided investigative leads and identified specific files requiring further examination.

![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/a21dee4c-5ca2-4d16-8b3e-5169bba91128)

---

# /etc/hosts

The `/etc/hosts` file contains local hostname mappings and network configuration information.

Review of this artifact did not reveal any suspicious modifications or notable findings.

![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/659736cb-1581-4aa7-bf54-d840f088a8ff)

---

# auth.log - Sudo Activity

The `auth.log` file contains authentication events, including sudo usage and commands executed with elevated privileges.

Review of this log identified activity involving:

- Steghide
- Telegram Desktop

These findings provided additional investigative leads regarding tools and applications used on the system.

![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/cb2659f4-b279-4148-9664-6ea5fa428044)

---

# /etc/passwd and /etc/shadow

The `/etc/passwd` and `/etc/shadow` files contain Linux user account information.

- `/etc/passwd` contains account information and user identifiers.
- `/etc/shadow` contains password hashes.

Password hashes can be extracted and analyzed using password recovery tools such as John the Ripper.

The recovered credentials can provide additional insight into user activity and access to protected files.

![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/c90b0368-1c75-492f-bf6f-7197a4b9827d)

---

# Findings

## Finding 1: Hidden Directory Containing Suspicious Files

A search for hidden directories was performed from the user's home directory.

Command used:

```bash
ls -ld .?*
```

A suspicious hidden directory was identified:

```
/home/ubuntuforensics/.for sales_copy
```

The directory contained a large number of image files.

The total file count was determined using:

```bash
ls -1 | wc -l
```

Result:

```
833 files
```

The hidden location and contents made this directory a significant artifact during the investigation.

---
# Finding 2: Suspicious Text Files

A review of user-created documents identified multiple text files containing information relevant to the investigation.

The following files were identified:

```
/home/ubuntuforensics/Documents/clients/clients_email
```

![Clients Email](https://github.com/garr3ttmjo/Writeups/assets/108881417/b182b084-1461-4936-9708-5e3b9dc7e0e7)

Additional suspicious content was identified in:

```
/home/ubuntuforensics/Documents/byName/for_clients.txt
```

![For Clients](https://github.com/garr3ttmjo/Writeups/assets/108881417/0f1490d3-90b5-4e7d-8005-a6de4ea14a1f)

These files contained information related to potential clients and activity relevant to the investigation.

---

# Finding 3: Deleted Image Recovery

Deleted files were examined through the Linux trash directory:

```
/home/ubuntuforensics/.local/share/Trash
```

The trash directory contained the following folders:

```
#
_
```

The deleted contents were recovered and analyzed.

Results:

```
130 deleted image files recovered
```

These recovered images were identified as suspicious based on the scenario requirements.

The recovery of deleted files demonstrated the importance of examining filesystem remnants, even after users attempt to remove evidence.

---

# Finding 4: Password Protected ZIP Archives

During filesystem examination, multiple ZIP archives were identified.

Two files were considered suspicious because their contents could not be viewed through FTK Imager, indicating that they were likely password protected.

Identified archives:

```
/Downloads/Images/#.zip

/Downloads/Images/_.zip
```

The password was later recovered through analysis of an encrypted private key artifact.

The archives were extracted using:

```bash
7z -p"root" e "#.zip"
```

The extracted files contained additional suspicious image evidence.

---

# Finding 5: Steganography Analysis

During artifact review, a directory containing unusual image files was identified:

```
/Documents/special client
```

The images appeared different from other images located throughout the filesystem and were analyzed for hidden data.

Steganography analysis was performed using Steghide.

The following command was used to extract hidden content:

```bash
steghide extract -sf image.jpg -p root
```

To analyze multiple images automatically:

```bash
for image in *.jpg; do
    steghide extract -sf "$image" -p root && echo "File found in: $image" || echo "No file found in: $image"
done
```

The analysis identified:

```
5 images containing embedded data
```

Hidden files were successfully extracted from the images.

![Steganography Extraction](https://github.com/garr3ttmjo/Writeups/assets/108881417/02e8c4bb-761f-413e-b1ba-80cb14228db5)

---

# Finding 6: Browser Artifact Analysis

Browser artifacts were analyzed to determine whether the user performed suspicious searches or accessed relevant websites.

The system contained evidence of two browsers:

- Firefox
- Tor Browser

Browser history was stored in:

```
places.sqlite
```

The SQLite databases were examined using DB Browser for SQLite.

The primary table analyzed was:

```
moz_places
```

This table contains browser history entries including visited URLs and search activity.

---

## Tor Browser Analysis

The Tor browser database confirmed that Tor had been used on the system.

However, no significant suspicious URLs were identified.

---

## Firefox Analysis

Firefox history contained multiple suspicious searches.

Identified search terms included:

```
f0r3ns1cs
F0r3ns1cs
```

Additional suspicious browsing activity included:

```
https://compactor.bandcamp.com/album/d1g1tal-f0r3ns1cs
```

The browser history also contained searches related to:

- Police departments
- Computer crime
- Digital forensics

These artifacts provided additional context regarding the user's online activity.

![Firefox History](https://github.com/garr3ttmjo/Writeups/assets/108881417/8fc5d3e8-75ee-4e0c-b9f9-7d1ece23f975)

![Browser History](https://github.com/garr3ttmjo/Writeups/assets/108881417/d44eb1e2-9566-44f8-9c03-b77c9734b12f)

---
# Finding 7: Known Hash Matching

During the investigation, law enforcement provided a database of known SHA1 hashes associated with previously identified illegal content.

The objective was to locate files on the system matching the following SHA1 values:

```
f1010ce85f3bac86c564403f454db46332f2937e

a9ce3a402bd06756afa6caa6cd985381cf544ed7

2144749eaea65bf7bc8d40a071eab444a382ee1d

ea7595007b7b9d8482fd3cc3d06035802bf79287
```

Initially, the Bash history artifact was reviewed and revealed that the user had previously calculated SHA1 hashes for four image files using:

```bash
sha1sum
```

This provided a lead for locating the files of interest.

Further filesystem analysis identified one matching file:

```
Downloads/Images/Images/Fig1848.jpg
```

The file produced the following SHA1 hash:

```
ea7595007b7b9d8482fd3cc3d06035802bf79287
```

Additional investigation identified a backup directory containing all four matching files:

```
/Downloads/Images Backup/Images
```

The recovered files were:

```
Figure216.jpg

Figure233.jpg

Figure235.jpg

Figure1848.jpg
```

The hashes were verified using:

```bash
for file in Figure216.jpg Figure233.jpg Figure235.jpg Figure1848.jpg; do sha1sum "$file"; done
```

The resulting hashes matched the provided law enforcement database.

![Hash Matching](https://github.com/garr3ttmjo/Writeups/assets/108881417/6860bf80-b331-4c66-9fe3-7d4c21a694f6)

---

# Finding 8: Encrypted Evidence Recovery

Encrypted files were identified during filesystem analysis.

A private encryption key was discovered:

```
Private.key
```

Further investigation identified encrypted image files located in:

```
Pics_to_clients
```

The encryption method was determined to be GPG, which is an implementation of the OpenPGP standard.

The recovered private key provided a method to decrypt the encrypted evidence.

---

## Password Recovery

The private key required a password before it could be used.

The key was first converted into a format compatible with John the Ripper:

```bash
gpg2john Private.key > gpghash.txt
```

John the Ripper was then used with a password wordlist:

```bash
john --wordlist=10-million-password-list-top-1000000.txt gpghash.txt
```

The password was successfully recovered:

```
root
```

---

## Importing the Private Key

The recovered private key was imported into GPG:

```bash
gpg --import Private.key
```

After importing the key, the encrypted files could be decrypted.

---

## Decrypting Evidence

The following command was used to decrypt multiple GPG encrypted files:

```bash
for i in *.gpg; do
    if [ -e "$i" ]; then
        gpg -d -o "$(echo "$i" | sed 's/\.gpg$//')" "$i"
    fi
done
```

The command successfully decrypted the encrypted image files.

![GPG Decryption](https://github.com/garr3ttmjo/Writeups/assets/108881417/cdd2bb46-42c2-4f9c-be79-c1a186696cde)

---

# Final Summary of Findings

The forensic examination of the Linux disk image identified multiple artifacts of investigative value.

The following evidence was recovered:

| Finding | Artifact |
|---|---|
| Hidden directory | `/home/ubuntuforensics/.for sales_copy` containing 833 files |
| Suspicious documents | Client-related text files |
| Deleted evidence | 130 recovered images from Linux trash |
| Password protected archives | `#.zip` and `_.zip` |
| Steganographic content | 5 images containing hidden data |
| Browser activity | Suspicious Firefox searches and URLs |
| Known hash matches | Four files matching provided SHA1 values |
| Encrypted evidence | GPG encrypted images recovered using private key |

---

# Conclusion

This investigation demonstrated the importance of examining multiple categories of Linux forensic artifacts, including filesystem metadata, user activity, deleted data, browser history, encryption artifacts, and hidden storage mechanisms.

Analysis of the evidence image resulted in the identification and recovery of:

- Hidden files and directories
- Deleted artifacts
- Suspicious documents
- Password-protected archives
- Steganographically hidden content
- Encrypted evidence
- Files matching known hash values

The investigation highlights how forensic analysts must examine both obvious and concealed artifacts to reconstruct user activity and identify evidence.

---