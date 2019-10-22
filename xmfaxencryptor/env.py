import os
import base64
import io
import subprocess
import shlex
import re
import uuid

from xmfaxencryptor.filecrypto import FileDecryptor, FileEncryptor, gen_random_key_256, KEY_BYTES_256


def _generate_random_key_id(generic_key_id):
    return generic_key_id + '-{' + str(uuid.uuid4()).upper() + '}'

def _generate_random_master_key_id():
    return _generate_random_key_id('MasterKey')

def _generate_random_server_key_id():
    return _generate_random_key_id('ServerKey')

def _generate_random_site_key_id(site_guid):
    return _generate_random_key_id(site_guid + '|SiteKey')

def _get_site_key_id_filename(media_store_keys_path, site_guid):
    filename = media_store_keys_path
    filename += os.sep
    filename += site_guid
    filename += os.sep
    filename += 'SiteKeyId.dat'
    return filename

def _get_key_filename(key_path, key_id, encrypted):
    filename = key_path
    filename += os.sep
    filename += key_id.replace('|', os.sep)
    filename += '.dat.xmencrypted' if encrypted else '.dat'
    return filename

def _create_clear_text_key_file(filename):
    new_key_dir = os.path.split(filename)[0]
    os.makedirs(new_key_dir, exist_ok=True)
    new_key = gen_random_key_256()

    #write it clear in base64 for human readers
    output_stream = open(filename, 'wb')
    output_stream.write(base64.b64encode(new_key))
    output_stream.close()

def _create_encrypted_key_file(filename, encrypt_with_key, encrypt_with_key_id):
    new_key_dir = os.path.split(filename)[0]
    os.makedirs(new_key_dir, exist_ok=True)
    new_key = gen_random_key_256()

    input_stream = io.BytesIO(new_key)
    encryptor = FileEncryptor(input_stream, encrypt_with_key_id, encrypt_with_key)
    output_stream = open(filename, 'wb')
    encryptor.encrypt(output_stream)
    output_stream.close()

def _create_site_key_id_file(filename, site_key_id):
    new_key_dir = os.path.split(filename)[0]
    os.makedirs(new_key_dir, exist_ok=True)
    output_stream = open(filename, 'wb')
    output_stream.write(site_key_id.encode(encoding='utf-8'))
    output_stream.close()

def _read_site_key_id_file(filename):
    input_stream = open(filename, 'rb')
    content = input_stream.read()
    input_stream.close()
    return content.decode(encoding='utf-8').strip()

def _get_site_key_id_or_create_site_key_id_and_key(media_store_keys_path, site_guid, encrypt_with_key, encrypt_with_key_id):
    site_key_id_filename = _get_site_key_id_filename(media_store_keys_path, site_guid)
    if os.path.isfile(site_key_id_filename):
        return _read_site_key_id_file(site_key_id_filename)
    else:
        site_key_id = _generate_random_site_key_id(site_guid)
        site_key_filename = _get_key_filename(media_store_keys_path, site_key_id, True)
        _create_encrypted_key_file(site_key_filename, encrypt_with_key, encrypt_with_key_id)
        _create_site_key_id_file(site_key_id_filename, site_key_id)
        return site_key_id

def _create_server_key_id_and_key(media_store_keys_path, encrypt_with_key, encrypt_with_key_id):
    server_key_id = _generate_random_server_key_id()
    server_key_filename = _get_key_filename(media_store_keys_path, server_key_id, True)
    _create_encrypted_key_file(server_key_filename, encrypt_with_key, encrypt_with_key_id)
    return server_key_id

def _create_master_key_id_and_key(media_store_master_key_path):
    master_key_id = _generate_random_master_key_id()
    master_key_filename = _get_key_filename(media_store_master_key_path, master_key_id, False)
    _create_clear_text_key_file(master_key_filename)
    return master_key_id

def _create_master_key_id():
    master_key_id = _generate_random_master_key_id()
    return master_key_id

def _get_site_and_instance_from_file_path(filename):
    m = re.search('(\\{[^\\{]*\\})\\\\(\\{[^\\{]*\\})', filename)
    if m:
        return (m.group(1), m.group(2))
    else:
        raise RuntimeError('Cannot extract site and instance from filename: ' + filename)


class SingleKeyProvider:
    def __init__(self, key):
        self.key = key
    def get_key(self, key_id):
        return self.key
    def get_key_filename(self, key_id):
        filename = key_id.replace('|', os.sep)
        filename += '.dat.xmencrypted'
        return filename


class XMKeyProvider:
    def __init__(self):
        self.master_key = None
        self.key_cache = {}
        self.xmre = None
        self.env = self._get_env()

    def get_key(self, key_id):
        if key_id == self.env['MasterKeyId']:
            if not self.master_key:
                master_key_command = self.env['MasterKeyCommand']
                if master_key_command:
                    result = subprocess.run(shlex.split(master_key_command), stdout=subprocess.PIPE)
                    self.master_key = self._decode_master_key(result.stdout)
                else:
                    filename = self._get_key_filename(key_id)
                    master_key_file = open(filename, 'rb')
                    self.master_key = self._decode_master_key(master_key_file.read())
                    master_key_file.close()
                if self.master_key is not None and len(self.master_key) != KEY_BYTES_256:
                    message = 'Invalid MasterKey length: ' + str(len(self.master_key) * 8) + ' bits, expected 256 bits'
                    self.master_key = None
                    raise RuntimeError(message)
            return self.master_key
        elif key_id in self.key_cache:
            return self.key_cache[key_id]
        else:
            content = None
            filename = self._get_key_filename(key_id)
            encrypted_file = FileDecryptor(filename)
            key = self.get_key(encrypted_file.key_id())
            if key:
                encrypted_file.set_key_and_validate(key)
                output = io.BytesIO()
                encrypted_file.decrypt(output)
                content = output.getvalue()
                self.key_cache[key_id] = content
            else:
                print('Key not found:', encrypted_file.key_id())
            encrypted_file.close()
            return content

    def get_key_filename(self, key_id):
        is_master_key = True if key_id == self.env['MasterKeyId'] else False
        filename = self.env['MediaStoreMasterKeyPath'] if is_master_key else self.env['MediaStoreKeysPath']
        filename += os.sep
        filename += key_id.replace('|', os.sep)
        filename += '.dat' if is_master_key else '.dat.xmencrypted'
        return filename

    def get_env(self):
        return self.env.copy()

    def _get_bin_path(self):
        result = subprocess.run(['REG', 'QUERY', 'HKLM\\SOFTWARE\\Interstar Technologies\\XMedius\\Directories', '/reg:32', '/v', 'BinPath'], stdout=subprocess.PIPE)
        if result.returncode == 0:
            lines = result.stdout.decode(encoding='utf-8').splitlines()
            for line in lines:
                if 'BinPath' in line:
                    m = re.search('[\\s]*BinPath[\\s]*REG_SZ[\\s]*(.*)', line)
                    if m:
                        return m.group(1)
        return None

    def _get_xmre_full_filename(self):
        if self.xmre is None:
            bin_path = self._get_bin_path()
            self.xmre = bin_path + '\\Util\\xmre.exe' if bin_path else 'xmre.exe'
        return self.xmre

    def _remove_leading_and_trailing_quotes(self, input):
        return input.strip('\'')

    def _get_registry_key_value(self, xmre, key, valuename, type):
        result = subprocess.run([xmre, key + '\\' + valuename, type], stdout=subprocess.PIPE)
        lines = result.stdout.decode(encoding='utf-8').splitlines()
        value = lines[-1].lstrip()
        prefix = valuename + ' = '
        stripped_value = self._remove_leading_and_trailing_quotes(value[len(prefix):] if value.startswith(prefix) else value)
        return base64.b64decode(stripped_value).decode(encoding='utf-8') if type == 'U' else stripped_value

    def _get_registry_key_boolean_value(self, xmre, key, valuename, default_value):
        value = self._get_registry_key_value(xmre, key, valuename, 'D')
        if len(value) > 0:
            return False if value == '0' else True
        return default_value

    def _set_registry_key_value(self, xmre, key, valuename, type, value):
        result = subprocess.run([xmre, key + '\\' + valuename, type, value], stdout=subprocess.PIPE)

    def _get_env(self):
        env_variables = {
            'MediaStoreMasterKeyPath'     : '',
            'MediaStoreKeysPath'          : '',
            'MediaStorePath'              : '',
            'SendingFaxQueueEncryption'   : False,
            'ReceivingFaxQueueEncryption' : False,
            'MasterKeyId'                 : '',
            'ServerKeyId'                 : '',
            'KeyMode'                     : '',
            'MasterKeyCommand'            : '',
            'MasterKeyCommandTimeout'     : 10,
        }
        xmre = self._get_xmre_full_filename()
        if not os.path.isfile(xmre):
            print('** File not found:', xmre)
        else:
            data_path = self._get_registry_key_value(xmre, 'Directories', 'DataPath', 'U')

            value = self._get_registry_key_value(xmre, 'Directories', 'MediaStoreMasterKeyPath', 'U')
            master_key_path = value if len(value) > 0 else data_path + '\\Security\\MediaStore'
            env_variables['MediaStoreMasterKeyPath'] = master_key_path

            value = self._get_registry_key_value(xmre, 'Directories', 'MediaStoreKeysPath', 'U')
            keys_path = value if len(value) > 0 else data_path + '\\Security\\MediaStore'
            env_variables['MediaStoreKeysPath'] = keys_path

            value = self._get_registry_key_value(xmre, 'Directories', 'MediaStorePath', 'U')
            mediastore_path = value if len(value) > 0 else data_path + '\\MediaStore'
            env_variables['MediaStorePath'] = mediastore_path

            encryption_enabled = self._get_registry_key_boolean_value(xmre, 'SecuritySettings\\MediaStoreEncryption', 'SendingFaxQueueEncryption', False)
            env_variables['SendingFaxQueueEncryption'] = encryption_enabled

            encryption_enabled = self._get_registry_key_boolean_value(xmre, 'SecuritySettings\\MediaStoreEncryption', 'ReceivingFaxQueueEncryption', False)
            env_variables['ReceivingFaxQueueEncryption'] = encryption_enabled

            master_key_id = self._get_registry_key_value(xmre, 'SecuritySettings\\MediaStoreEncryption', 'MasterKeyId', 'U')
            env_variables['MasterKeyId'] = master_key_id

            server_key_id = self._get_registry_key_value(xmre, 'SecuritySettings\\MediaStoreEncryption', 'ServerKeyId', 'U')
            env_variables['ServerKeyId'] = server_key_id

            value = self._get_registry_key_value(xmre, 'SecuritySettings\\MediaStoreEncryption', 'KeyMode', 'S')
            key_mode = value if len(value) > 0 else 'Server'
            env_variables['KeyMode'] = key_mode

            master_key_command = self._get_registry_key_value(xmre, 'SecuritySettings\\MediaStoreEncryption', 'MasterKeyCommand', 'U')
            env_variables['MasterKeyCommand'] = master_key_command

            value = self._get_registry_key_value(xmre, 'SecuritySettings\\MediaStoreEncryption', 'MasterKeyCommandTimeout', 'D')
            master_key_command_timeout = int(value) if len(value) > 0 else 10
            env_variables['MasterKeyCommandTimeout'] = master_key_command_timeout

        return env_variables

    def _decode_master_key(self, value):
        if value.startswith(b'BASE64:'):
            return base64.b64decode(value.decode(encoding='utf-8')[7:].rstrip())
        elif value.startswith(b'HEX:0x'):
            return bytes.fromhex(value.decode(encoding='utf-8')[6:].rstrip())
        elif value.startswith(b'HEX:'):
            return bytes.fromhex(value.decode(encoding='utf-8')[4:].rstrip())
        elif value.startswith(b'0x'):
            return bytes.fromhex(value.decode(encoding='utf-8')[2:].rstrip())
        elif value.startswith(b'BIN:'):
            return value[4:36]
        else:
            return base64.b64decode(value.decode(encoding='utf-8').rstrip())

    def _get_key_filename(self, key_id):
        filename = self.get_key_filename(key_id)
        if not os.path.isfile(filename):
            print('Cannot auto-create', key_id, 'for this operation')
        return filename

    def get_default_key_id_for_file(self, filename):
        mode = self.env['KeyMode'].lower()
        if mode == 'server':
            self._init_master_key()
            self._init_server_key()
            return self.env['ServerKeyId']
        elif mode == 'site':
            self._init_master_key()
            site_guid = _get_site_and_instance_from_file_path(filename)[0]
            master_key_id = self.env['MasterKeyId']
            return _get_site_key_id_or_create_site_key_id_and_key(self.env['MediaStoreKeysPath'], site_guid, self.get_key(master_key_id), master_key_id)
        else:
            raise RuntimeError('Invalid key mode: ' + self.env['KeyMode'])

    def _init_master_key(self):
        if not self.env['MasterKeyId']:
            if self.env['MasterKeyCommand']:
                self.env['MasterKeyId'] = _create_master_key_id()
            else:
                self.env['MasterKeyId'] = _create_master_key_id_and_key(self.env['MediaStoreMasterKeyPath'])
            xmre = self._get_xmre_full_filename()
            self._set_registry_key_value(xmre, 'SecuritySettings\\MediaStoreEncryption', 'MasterKeyId', 'S', self.env['MasterKeyId'])

    def _init_server_key(self):
        if not self.env['ServerKeyId']:
            master_key_id = self.env['MasterKeyId']
            self.env['ServerKeyId'] = _create_server_key_id_and_key(self.env['MediaStoreKeysPath'], self.get_key(master_key_id), master_key_id)
            xmre = self._get_xmre_full_filename()
            self._set_registry_key_value(xmre, 'SecuritySettings\\MediaStoreEncryption', 'ServerKeyId', 'S', self.env['ServerKeyId'])

    def get_master_key_id(self):
        return self.env['MasterKeyId']
