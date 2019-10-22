**XM Fax** is XMedius's advanced fax server solution built on the public standard T.38 Fax over IP (FoIP) protocol.

XM Fax 9.0 added Encryption at Rest to its features.  When enabled, all new fax files are stored encrypted in the
local mediastore, using a proprietary file format which contains the name of the key needed to decrypt the file and
a validation hash used to validate success of decryption.  Each fax files are encrypted with a key, itself stored
encrypted with the master key, using the same proprietary file format.


# xmfaxencryptor

This Python module, used as a command line tool, allows you to perform various operations on the files and keys used
by XM Fax, such as:

* Encrypt or decrypt single files and keys
* Encrypt or decrypt the mediastore, in part or in whole
* Re-encrypt the mediastore using new keys, in part or in whole
* Re-encrypt the keys using a new master key
* Create new keys
* Display information of an encrypted file


# Table of Contents

* [Installation](#installation)
* [Usage](#usage)
* [Examples](#examples)
* [License](#license)
* [Credits](#credits)


# Installation

## Prerequisites

- Python version 3.7+
- The XM Fax On-Premises solution, provided by [XMedius](https://www.xmedius.com?source=xmfaxencryptor)

## Install Package

```python
pip install https://github.com/xmedius/xmfaxencryptor/tarball/master
```


# Usage

python.exe -m xmfaxencryptor


## Operations on Files:

### Display information of an encrypted file
```
python.exe -m xmfaxencryptor describe filename
```

Param    | Definition
---------|-----------
filename | The encrypted file full path


### Encrypt a single file
```
python.exe -m xmfaxencryptor encrypt filename out-filename key-id base64-encoded-key
```

Param              | Definition
-------------------|-----------
filename           | The non-encrypted file full path
out-filename       | The encrypted file full path
key-id             | The id of the key used to encrypt this file
base64-encoded-key | The key, base64 encoded, to use to encrypt this file


### Decrypt a single file
```
python.exe -m xmfaxencryptor decrypt filename out-filename base64-encoded-key
```

Param              | Definition
-------------------|-----------
filename           | The encrypted file full path
out-filename       | The non-encrypted file full path
base64-encoded-key | The key, base64 encoded, to use to decrypt this file


### Decrypt a key file
```
python.exe -m xmfaxencryptor decrypt-key key-filename base64-encoded-master-key
```

Param                     | Definition
--------------------------|-----------
key-filename              | The key file full path
base64-encoded-master-key | The key, base64 encoded, to use to decrypt this file


## Operations on Files and Mediastore on the Fax Server:

### Show Encryption at Rest Configuration
```
python.exe -m xmfaxencryptor xmconfig
```

### Display information of an encrypted file
```
python.exe -m xmfaxencryptor xmdescribe filename
```

Param    | Definition
---------|-----------
filename | The encrypted file full path


### Encrypt a single file
```
python.exe -m xmfaxencryptor xmencrypt filename out-filename key-id
```

Param              | Definition
-------------------|-----------
filename           | The non-encrypted file full path
out-filename       | The encrypted file full path
key-id             | The id of an existing key to use to encrypt this file


### Decrypt a single file
```
python.exe -m xmfaxencryptor xmdecrypt filename out-filename
```

Param              | Definition
-------------------|-----------
filename           | The encrypted file full path
out-filename       | The non-encrypted file full path


### Create a key file
```
python.exe -m xmfaxencryptor xmencrypt-key key-id base64-encoded-key
```

The key file will be encrypted using the master key and stored in the Key folder based on its key-id

Param              | Definition
-------------------|-----------
key-id             | The new key id
base64-encoded-key | The new key, base64 encoded


### Decrypt a key file
```
python.exe -m xmfaxencryptor xmdecrypt-key key-id
```

Param  | Definition
-------|-----------
key-id | The id of an existing key


### Encrypt the mediastore, in part or in whole
```
python.exe -m xmfaxencryptor xmencrypt-mediastore {SendingFaxQueue|ReceivingFaxQueue|SendingAndReceivingFaxQueues} {All|sub-store} [backup-folder]
```

Files already encrypted won't be re-encrypted

Param         | Definition
--------------|-----------
store         | One of SendingFaxQueue or ReceivingFaxQueue or SendingAndReceivingFaxQueues
sub-store     | One of All (for all sites) or the Site Guid
backup-folder | Optional backup folder where non-encrypted files will be copied before encryption


### Re-encrypt the mediastore using new keys, in part or in whole
```
python.exe -m xmfaxencryptor xmreencrypt-mediastore {SendingFaxQueue|ReceivingFaxQueue|SendingAndReceivingFaxQueues} {All|sub-store} [backup-folder]
```

Files already encrypted with the latest key won't be re-encrypted

Param         | Definition
--------------|-----------
store         | One of SendingFaxQueue or ReceivingFaxQueue or SendingAndReceivingFaxQueues
sub-store     | One of All (for all sites) or the Site Guid
backup-folder | Optional backup folder where non-encrypted / encrypted files will be copied before encryption / re-encryption


### Decrypt the mediastore, in part or in whole
```
python.exe -m xmfaxencryptor xmdecrypt-mediastore {SendingFaxQueue|ReceivingFaxQueue|SendingAndReceivingFaxQueues} {All|sub-store} [backup-folder]
```

Param         | Definition
--------------|-----------
store         | One of SendingFaxQueue or ReceivingFaxQueue or SendingAndReceivingFaxQueues
sub-store     | One of All (for all sites) or the Site Guid
backup-folder | Optional backup folder where encrypted files will be copied before decryption



### Re-encrypt the keys using a new master key
```
python.exe -m xmfaxencryptor xmchange-mediastore-master-key base64-encoded-master-key new-base64-encoded-master-key new-master-key-id [backup-folder]
```

Param                         | Definition
------------------------------|-----------
base64-encoded-master-key     | The key, base64 encoded, to use to decrypt the key files
new-base64-encoded-master-key | The new key, base64 encoded, to use to encrypt the key files
new-master-key-id             | The id of the new key used to encrypt the key files


### Backup all Keys except the Master Key
```
python.exe -m xmfaxencryptor xmbackup-keys backup-folder [timestamp]
```

Param         | Definition
--------------|-----------
backup-folder | Backup folder where encrypted key files will be copied
timestamp     | Optional string to append to the key filenames in the backup folder


### Backup the Master Key to a clear text file
```
python.exe -m xmfaxencryptor xmbackup-master-key backup-folder [timestamp]
```

Param         | Definition
--------------|-----------
backup-folder | Backup folder where the master key will be written in clear text to a file
timestamp     | Optional string to append to the master key filename in the backup folder


## Other Operations:

### Create New Key
```
python.exe -m xmfaxencryptor create-key
```


# Examples

### Encrypt both SendingFaxQueue and ReceivingFaxQueue mediastores for all sites
```
python.exe -m xmfaxencryptor xmencrypt-mediastore SendingAndReceivingFaxQueues All
```

* Note: only non-encrypted files will be encrypted by this command
* Note: this operation is not mandatory, XM Fax will serve all non-encrypted files even if MediaStore Encryption is enabled


### Re-encrypt both SendingFaxQueue and ReceivingFaxQueue mediastores for only the site whose site guid is {435C2E8E-E43D-46B3-81DA-18527274062D}
```
python.exe -m xmfaxencryptor xmreencrypt-mediastore SendingAndReceivingFaxQueues "{435C2E8E-E43D-46B3-81DA-18527274062D}"
```

* Note: only non-encrypted files and files not encrypted with the current key will be encrypted by this command
* Note: this operation is not mandatory, XM Fax will serve all files encrypted by previous keys


### Decrypt both SendingFaxQueue and ReceivingFaxQueue mediastores for all sites
```
python.exe -m xmfaxencryptor xmdecrypt-mediastore SendingAndReceivingFaxQueues All
```

* Note: this operation is not mandatory, XM Fax will serve all encrypted files even if MediaStore Encryption is disabled


### Decrypt one file on the XM Fax server
```
python.exe -m xmfaxencryptor xmdecrypt "C:\Program Files (x86)\XMediusFAX\Data\MediaStore\ReceivingFaxQueue\{435C2E8E-E43D-46B3-81DA-18527274062D}\{DC362610-7179-42D4-9DB9-C3BC7C1F3214}\00\00\00\00\00\00\00\00.TIF.xmencrypted" 00.TIF
```

### Decrypt one file anywhere
If you don't have the master key, get it from the XM Fax server:
```
python.exe -m xmfaxencryptor xmconfig
```

Using the master key id obtained from the previous command, for example MasterKey-{5BE60662-AC36-4F8D-A0AE-0340D0525E5B}, get the master key:
```
python.exe -m xmfaxencryptor xmdecrypt-key MasterKey-{5BE60662-AC36-4F8D-A0AE-0340D0525E5B}
```

Get the key id needed to decrypt the file:
```
python.exe -m xmfaxencryptor describe 00.TIF.xmencrypted
```

Decrypt the key using the key id obtained from the previous command, for example {435C2E8E-E43D-46B3-81DA-18527274062D}|SiteKey, and using the master key obtained earlier, for example cptctJt0a1qdy5LoJKXZ4TZ5P4hnWlJlZ+tvlRsmnzs=
```
python.exe -m xmfaxencryptor decrypt-key "C:\Program Files (x86)\XMediusFAX\Data\Security\MediaStore\{435C2E8E-E43D-46B3-81DA-18527274062D}\SiteKey.dat.xmencrypted" cptctJt0a1qdy5LoJKXZ4TZ5P4hnWlJlZ+tvlRsmnzs=
```

Decrypt the file using the key obtained from the previous command, for example iVpqAXJIjwmfVw7XC4OeNb6iqUOOBa5QHMZmjvFBbdQ=
```
python.exe -m xmfaxencryptor decrypt 00.TIF.xmencrypted 00.TIF iVpqAXJIjwmfVw7XC4OeNb6iqUOOBa5QHMZmjvFBbdQ=
```

### Change the MasterKey
Stop the local FaxManager service

Get the current master key from the XM Fax server:
```
python.exe -m xmfaxencryptor xmconfig
```

Using the master key id obtained from the previous command, for example MasterKey-{5BE60662-AC36-4F8D-A0AE-0340D0525E5B}, get the master key:
```
python.exe -m xmfaxencryptor xmdecrypt-key MasterKey-{5BE60662-AC36-4F8D-A0AE-0340D0525E5B}
```

If you don't have a new master key, create one:
```
python.exe -m xmfaxencryptor create-key
```

Re-encrypt all key files using the new master key obtained from the previous command, for example tvouMVx7RDfFCdh9d4bMzhye92+xB5wOympmNQ96ycg=, and the current master key
obtained earlier, for example cptctJt0a1qdy5LoJKXZ4TZ5P4hnWlJlZ+tvlRsmnzs=
```
python.exe -m xmfaxencryptor xmchange-mediastore-master-key cptctJt0a1qdy5LoJKXZ4TZ5P4hnWlJlZ+tvlRsmnzs= tvouMVx7RDfFCdh9d4bMzhye92+xB5wOympmNQ96ycg= MyNewMasterKeyId
```

If the master key is obtained reading a clear text file, save it in MyNewMasterKeyId.dat in the MediaStoreMasterKeyPath (see the output of the xmconfig command ran at the beginning).
Otherwise, if the master key is obtained by calling a command line tool, update it where appropriate.

Update the MasterKeyId registry key:
```
Key :  HKLM\SOFTWARE\Wow6432Node\Interstar Technologies\XMedius\SecuritySettings\MediaStoreEncryption
Type:  REG_SZ (String value)
Name:  MasterKeyId
Data:  MyNewMasterKeyId
```

Start the local FaxManager service


# License

xmfaxencryptor is distributed under [MIT License](https://github.com/xmedius/xmfaxencryptor/blob/master/LICENSE).


# Credits

xmfaxencryptor is developed, maintained and supported by [XMedius Solutions Inc.](https://www.xmedius.com?source=xmfaxencryptor)
The names and logos for xmfaxencryptor are trademarks of XMedius Solutions Inc.

![XMedius Logo](https://s3.amazonaws.com/xmc-public/images/xmedius-site-logo.png)
