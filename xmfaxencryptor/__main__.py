import os
import sys
import base64
import io
import shutil
import datetime

from xmfaxencryptor.env import SingleKeyProvider, XMKeyProvider
from xmfaxencryptor.filecrypto import FileDecryptor, FileEncryptor, gen_random_key_256, KEY_BYTES_256

_XX_ENCRYPTED_EXTENSION = '.xmencrypted'

class LogFile:
    def __init__(self, f):
        self.f = f
    def __enter__(self):
        return self
    def __exit__(self, type, value, traceback):
        self.f.close()
    def _write(self, what):
        s = what if type(what) in (str,) else str(what)
        self.f.write(s.encode(encoding='utf-8'))
    def print(self, *args):
        for what in args:
            self._write(what)
            self.f.write(b' ')
        self.f.write(os.linesep.encode(encoding='utf-8'))
    def name(self):
        return self.f.name

def open_log_file(filename):
    log_dir = os.path.dirname(os.path.abspath(__file__)) + os.sep + 'log'
    os.makedirs(log_dir, exist_ok=True)
    full_filename = log_dir + os.sep + filename + datetime.datetime.now().strftime('.%Y%m%d%H%M%S.log')
    return open(full_filename, 'wb')

def _describe(filename, key_provider):
    encrypted_file = FileDecryptor(filename)
    print('')
    print('  Size  :', encrypted_file.decrypted_size())
    print('  Cipher:', encrypted_file.cipher_id())
    key_id = encrypted_file.key_id()
    key_filename = key_provider.get_key_filename(key_id)
    key_found = os.path.isfile(key_filename)
    print('  Key Id:', key_id, ' -> ', key_filename, ('' if key_found else ' *** NOT FOUND ***'))
    encrypted_file.close()

def _decrypt(filename, out_filename, key_provider):
    success = False
    encrypted_file = FileDecryptor(filename)
    key_id = encrypted_file.key_id()
    if not key_id and encrypted_file.decrypted_size() == 0:
        output = open(out_filename, 'wb')
        output.close()
        success = True
    else:
        key = key_provider.get_key(key_id)
        if key:
            encrypted_file.set_key_and_validate(key)
            output = open(out_filename, 'wb')
            encrypted_file.decrypt(output)
            output.close()
            success = True
        else:
            print('Key not found:', key_id)
    encrypted_file.close()
    return success

def _get_decrypted_content(filename, key_provider):
    content = None
    encrypted_file = FileDecryptor(filename)
    key = key_provider.get_key(encrypted_file.key_id())
    if key:
        encrypted_file.set_key_and_validate(key)
        output = io.BytesIO()
        encrypted_file.decrypt(output)
        content = output.getvalue()
    else:
        print('Key not found:', encrypted_file.key_id())
    encrypted_file.close()
    return content

def _encrypt_key_file(key_id, key, key_provider):
    key_filename = key_provider.get_key_filename(key_id)
    key_folder = os.path.split(key_filename)[0]
    os.makedirs(key_folder, exist_ok=True)
    if os.path.isfile(key_filename):
        raise RuntimeError(key_filename + ' already exists')
    master_key_id = key_provider.get_master_key_id()
    encryptor = FileEncryptor(io.BytesIO(key), master_key_id, key_provider.get_key(master_key_id))
    output_stream = open(key_filename, 'wb')
    encryptor.encrypt(output_stream)
    output_stream.close()
    return key_filename

def _encrypt(filename, out_filename, key_id, key_provider):
    key = key_provider.get_key(key_id)
    if key:
        input_stream = open(filename, 'rb')
        encryptor = FileEncryptor(input_stream, key_id, key)
        output_stream = open(out_filename, 'wb')
        encryptor.encrypt(output_stream)
        output_stream.close()
        input_stream.close()
        return True
    else:
        print('Key not found:', key_id)
        return False

def _reencrypt(encrypted_file, out_filename, key_id, key_provider):
    key = key_provider.get_key(encrypted_file.key_id())
    if not key:
        print('Key not found:', encrypted_file.key_id())
        return False
    encrypted_file.set_key_and_validate(key)
    key = key_provider.get_key(key_id)
    if not key:
        print('Key not found:', key_id)
        return False
    encryptor = FileEncryptor(encrypted_file, key_id, key)
    output_stream = open(out_filename, 'wb')
    encryptor.encrypt(output_stream)
    output_stream.close()
    return True

def _base64_decode_key(base64_encoded_key):
    key = base64.b64decode(base64_encoded_key)
    if len(key) != KEY_BYTES_256:
        raise RuntimeError('Invalid key length: ' + str(base64_encoded_key) + ' is ' + str(len(key) * 8) + ' bits, expected 256 bits')
    return key


def _print_key_status(keyid, current_keyid, directory, file_extension, command):
    filename = current_keyid + file_extension
    auto_create = False if current_keyid else True
    if current_keyid:
        print(' ', keyid, ':', current_keyid)
    else:
        print(' ', keyid)
    if command:
        print('    will be obtained by calling:', command)
    elif current_keyid and os.path.isfile(directory + '\\' + filename):
        print('    found in', directory)
    elif auto_create:
        print('    NOT found in', directory, ', will be auto-created')
    else:
        print('    ** NOT found in', directory, ', will NOT be auto-created')

def _print_env(key_provider):
    env_variables = key_provider.get_env()
    print('')
    print('  MediaStoreMasterKeyPath    :', env_variables['MediaStoreMasterKeyPath'])
    print('  MediaStoreKeysPath         :', env_variables['MediaStoreKeysPath'])
    print('  MediaStorePath             :', env_variables['MediaStorePath'])
    print('  SendingFaxQueueEncryption  :', env_variables['SendingFaxQueueEncryption'])
    print('  ReceivingFaxQueueEncryption:', env_variables['ReceivingFaxQueueEncryption'])
    print('  MasterKeyId                :', env_variables['MasterKeyId'])
    print('  ServerKeyId                :', env_variables['ServerKeyId'])
    print('  KeyMode                    :', env_variables['KeyMode'])
    print('  MasterKeyCommand           :', env_variables['MasterKeyCommand'])
    print('  MasterKeyCommandTimeout    :', env_variables['MasterKeyCommandTimeout'])
    print('')
    _print_key_status('MasterKey', env_variables['MasterKeyId'], env_variables['MediaStoreMasterKeyPath'], '.dat', env_variables['MasterKeyCommand'])
    print('')
    _print_key_status('ServerKey', env_variables['ServerKeyId'], env_variables['MediaStoreKeysPath'], '.dat.xmencrypted', None)

def _print_results(what, counts, log_file, print_log_file_name=True):
    print('')
    log_file.print('')
    print(what + ':')
    log_file.print(what + ':')
    print('  Success:', counts[0])
    log_file.print('  Success:', counts[0])
    print('  Failure:', counts[1])
    log_file.print('  Failure:', counts[1])
    print('  Skipped:', counts[2])
    log_file.print('  Skipped:', counts[2])
    log_file.print('')
    if print_log_file_name:
        print('\nDetails can be found in', log_file.name())

def _backup_file(source, dest, log_file):
    dest_dir = os.path.split(dest)[0]
    os.makedirs(dest_dir, exist_ok=True)
    if os.path.isfile(dest):
        dest += datetime.datetime.now().strftime(".%Y%m%d%H%M%S")
    shutil.copyfile(source, dest)
    log_file.print(source)
    log_file.print('    copied to', dest)

def _create_directory_if(dir):
    if dir:
        os.makedirs(dir, exist_ok=True)

def _encrypt_mediastore(root_dir, backup_dir, store, sub_store, key_mode, key_provider, log_file, reencrypt):
    root_dir_len = len(root_dir)
    check_files = False # don't encrypt files in the root
    success_count = 0
    failure_count = 0
    skipped_count = 0
    walk_root = root_dir + os.sep + store
    if sub_store:
        walk_root += os.sep + sub_store
        check_files = True
    for root, dirs, files in os.walk(walk_root):
        if check_files:
            for file in files:
                if file != '_entries.dat':
                    filename, file_extension = os.path.splitext(file)
                    if file_extension != _XX_ENCRYPTED_EXTENSION:
                        full_filename = root + os.sep + file
                        full_filename_out = full_filename + _XX_ENCRYPTED_EXTENSION
                        if os.path.isfile(full_filename_out) and backup_dir:
                            backup_full_filename_out = backup_dir + root[root_dir_len:] + os.sep + file + _XX_ENCRYPTED_EXTENSION
                            _backup_file(full_filename_out, backup_full_filename_out, log_file)
                        if backup_dir:
                            backup_full_filename = backup_dir + root[root_dir_len:] + os.sep + file
                            _backup_file(full_filename, backup_full_filename, log_file)
                        success = False
                        log_file.print(full_filename)
                        try:
                            key_id = key_provider.get_default_key_id_for_file(full_filename)
                            success = _encrypt(full_filename, full_filename_out, key_id, key_provider)
                        except Exception as ex:
                            log_file.print('   ', ex)
                        if success:
                            log_file.print('    encrypted to', full_filename_out)
                            os.remove(full_filename)
                            success_count += 1
                        else:
                            log_file.print('    *** failed to encrypt to', full_filename_out)
                            failure_count += 1
                    elif reencrypt:
                        full_filename = root + os.sep + file
                        log_file.print(full_filename)
                        try:
                            new_key_id = key_provider.get_default_key_id_for_file(full_filename)
                            encrypted_file = FileDecryptor(full_filename)
                            current_key_id = encrypted_file.key_id()
                            if not current_key_id and encrypted_file.decrypted_size() == 0:
                                log_file.print('    skipping reencrypt as file is empty')
                                encrypted_file.close()
                                skipped_count += 1
                            elif new_key_id == current_key_id:
                                log_file.print('    already encrypted with', new_key_id)
                                encrypted_file.close()
                                skipped_count += 1
                            else:
                                success = False
                                full_filename_out = full_filename + '.new'
                                try:
                                    success = _reencrypt(encrypted_file, full_filename_out, new_key_id, key_provider)
                                except Exception as ex:
                                    log_file.print('   ', ex)
                                encrypted_file.close()
                                if success:
                                    log_file.print('    reencrypted')
                                    if backup_dir:
                                        backup_full_filename = backup_dir + root[root_dir_len:] + os.sep + file
                                        _backup_file(full_filename, backup_full_filename, log_file)
                                    os.replace(full_filename_out, full_filename)
                                    success_count += 1
                                else:
                                    log_file.print('    *** failed to encrypt')
                                    failure_count += 1
                        except Exception as ex:
                            log_file.print('   ', ex)
                            failure_count += 1
                    else:
                        skipped_count += 1
        check_files = True
    return (success_count, failure_count, skipped_count)

def _decrypt_mediastore(root_dir, backup_dir, store, sub_store, key_provider, log_file):
    root_dir_len = len(root_dir)
    check_files = False # don't decrypt files in the root
    success_count = 0
    failure_count = 0
    skipped_count = 0
    walk_root = root_dir + os.sep + store
    if sub_store:
        walk_root += os.sep + sub_store
        check_files = True
    for root, dirs, files in os.walk(walk_root):
        if check_files:
            for file in files:
                if file != '_entries.dat':
                    filename, file_extension = os.path.splitext(file)
                    if file_extension == _XX_ENCRYPTED_EXTENSION:
                        full_filename = root + os.sep + file
                        full_filename_out = root + os.sep + filename
                        if os.path.isfile(full_filename_out) and backup_dir:
                            backup_full_filename_out = backup_dir + root[root_dir_len:] + os.sep + filename
                            _backup_file(full_filename_out, backup_full_filename_out, log_file)
                        if backup_dir:
                            backup_full_filename = backup_dir + root[root_dir_len:] + os.sep + file
                            _backup_file(full_filename, backup_full_filename, log_file)
                        success = False
                        log_file.print(full_filename)
                        try:
                            success = _decrypt(full_filename, full_filename_out, key_provider)
                        except Exception as ex:
                            log_file.print('   ', ex)
                        if success:
                            log_file.print('    decrypted to', full_filename_out)
                            os.remove(full_filename)
                            success_count += 1
                        else:
                            log_file.print('    *** failed to decrypt to', full_filename_out)
                            failure_count += 1
                    else:
                        skipped_count += 1
        check_files = True
    return (success_count, failure_count, skipped_count)

def _reencrypt_keys(root_dir, backup_dir, master_key, new_master_key, new_master_key_id, log_file):
    backup_ext = datetime.datetime.now().strftime(".%Y%m%d%H%M%S")
    master_key_provider = SingleKeyProvider(master_key)
    success_count = 0
    reencryption_failed = False
    names = []

    try:
        root_dir_len = len(root_dir)
        for root, dirs, files in os.walk(root_dir):
            for file in files:
                filename, file_extension = os.path.splitext(file)
                if file_extension == _XX_ENCRYPTED_EXTENSION:
                    full_filename = root + os.sep + file
                    full_filename_backup = full_filename + backup_ext
                    names.append((full_filename, full_filename_backup))
                    os.rename(full_filename, full_filename_backup)
                    if backup_dir:
                        backup_full_filename = backup_dir + root[root_dir_len:] + os.sep + file + backup_ext
                        _backup_file(full_filename_backup, backup_full_filename, log_file)
                    log_file.print(full_filename)
                    key = _get_decrypted_content(full_filename_backup, master_key_provider)
                    if key:
                        encryptor = FileEncryptor(io.BytesIO(key), new_master_key_id, new_master_key)
                        output_stream = open(full_filename, 'wb')
                        encryptor.encrypt(output_stream)
                        output_stream.close()
                        log_file.print('    done')
                        success_count += 1
                    else:
                        raise RuntimeError('Key not found for', full_filename)
    except Exception as ex:
        print('*** ERROR ***:', ex)
        log_file.print('*** ERROR ***:', ex)
        reencryption_failed = True

    if reencryption_failed:
        print('\nRe-encryption failed, reverting to original key files...')
        log_file.print('Re-encryption failed, reverting to original key files...')
        for name in names:
            if os.path.isfile(name[1]):
                if os.path.isfile(name[0]):
                    os.remove(name[0])
                os.rename(name[1], name[0])
                log_file.print(name[1], 'reverted to', name[0])
        print('Re-encryption failed, reverting to original key files...Done')
        log_file.print('Re-encryption failed, reverting to original key files...Done')
        return (0, 1, 0)
    else:
        for name in names:
            os.remove(name[1])
        return (success_count, 0, 0)

def _encrypt_mediastores(sending, receiving, sub_store, backup_dir, key_provider, log_file, reencrypt):
    _create_directory_if(backup_dir)
    env_variables = key_provider.get_env()
    root_dir = env_variables['MediaStorePath']
    key_mode = env_variables['KeyMode']
    if receiving:
        inbound_counts = _encrypt_mediastore(root_dir, backup_dir, 'ReceivingFaxQueue', sub_store, key_mode, key_provider, log_file, reencrypt)
        _print_results('Inbound faxes', inbound_counts, log_file, False)
    if sending:
        outbound_counts = _encrypt_mediastore(root_dir, backup_dir, 'SendingFaxQueue', sub_store, key_mode, key_provider, log_file, reencrypt)
        _print_results('Outbound faxes', outbound_counts, log_file)

def _decrypt_mediastores(sending, receiving, sub_store, backup_dir, key_provider, log_file):
    _create_directory_if(backup_dir)
    env_variables = key_provider.get_env()
    root_dir = env_variables['MediaStorePath']
    if receiving:
        inbound_counts = _decrypt_mediastore(root_dir, backup_dir, 'ReceivingFaxQueue', sub_store, key_provider, log_file)
        _print_results('Inbound faxes', inbound_counts, log_file, False)
    if sending:
        outbound_counts = _decrypt_mediastore(root_dir, backup_dir, 'SendingFaxQueue', sub_store, key_provider, log_file)
        _print_results('Outbound faxes', outbound_counts, log_file)

def _change_mediastore_master_key(backup_dir, master_key, new_master_key, new_master_key_id, key_provider, log_file):
    _create_directory_if(backup_dir)
    env_variables = key_provider.get_env()
    root_dir = env_variables['MediaStoreKeysPath']
    counts = _reencrypt_keys(root_dir, backup_dir, master_key, new_master_key, new_master_key_id, log_file)
    _print_results('Keys', counts, log_file)

def _backup_keys(backup_dir, backup_ext, key_provider, log_file):
    _create_directory_if(backup_dir)
    env_variables = key_provider.get_env()
    root_dir = env_variables['MediaStoreKeysPath']
    root_dir_len = len(root_dir)
    count = 0
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            filename, file_extension = os.path.splitext(file)
            if file_extension == _XX_ENCRYPTED_EXTENSION:
                full_filename = root + os.sep + file
                backup_full_filename = backup_dir + root[root_dir_len:] + os.sep + file
                if backup_ext:
                    backup_full_filename += backup_ext
                _backup_file(full_filename, backup_full_filename, log_file)
                count += 1
    _print_results('Keys', (count, 0, 0), log_file)

def _backup_master_key(backup_dir, backup_ext, key_provider):
    master_key_id = key_provider.get_master_key_id()
    key = key_provider.get_key(master_key_id)
    if key:
        os.makedirs(backup_dir, exist_ok=True)
        backup_file_name = backup_dir + os.sep + master_key_id + '.dat'
        if backup_ext:
            backup_file_name += backup_ext
        backup_file = open(backup_file_name, 'wb')
        backup_file.write(base64.b64encode(key))
        backup_file.close()
        print('Done')
    else:
        print('Key Id: MasterKey *** NOT FOUND ***')


def _get_arg(argv, index, default_value):
    return argv[index] if len(argv) > index else default_value

def _main():
    done = False
    action = _get_arg(sys.argv, 1, '')
    if action == 'describe':
        filename = _get_arg(sys.argv, 2, None)
        if filename:
            done = True
            _describe(filename, SingleKeyProvider(None))
    elif action == 'encrypt':
        filename = _get_arg(sys.argv, 2, None)
        out_filename = _get_arg(sys.argv, 3, None)
        key_id = _get_arg(sys.argv, 4, None)
        base64_encoded_key = _get_arg(sys.argv, 5, None)
        if filename and out_filename and key_id and base64_encoded_key:
            done = True
            key = _base64_decode_key(base64_encoded_key)
            _create_directory_if(os.path.dirname(out_filename))
            success = _encrypt(filename, out_filename, key_id, SingleKeyProvider(key))
            print('Done' if success else 'FAILED')
    elif action == 'decrypt':
        filename = _get_arg(sys.argv, 2, None)
        out_filename = _get_arg(sys.argv, 3, None)
        base64_encoded_key = _get_arg(sys.argv, 4, None)
        if filename and out_filename and base64_encoded_key:
            done = True
            key = _base64_decode_key(base64_encoded_key)
            _create_directory_if(os.path.dirname(out_filename))
            success = _decrypt(filename, out_filename, SingleKeyProvider(key))
            print('Done' if success else 'FAILED')
    elif action == 'decrypt-key':
        filename = _get_arg(sys.argv, 2, None)
        base64_encoded_key = _get_arg(sys.argv, 3, None)
        if filename and base64_encoded_key:
            done = True
            key = _base64_decode_key(base64_encoded_key)
            content = _get_decrypted_content(filename, SingleKeyProvider(key))
            if content:
                print(base64.b64encode(content).decode())
    elif action == 'xmconfig':
        done = True
        _print_env(XMKeyProvider())
    elif action == 'xmdescribe':
        filename = _get_arg(sys.argv, 2, None)
        if filename:
            done = True
            _describe(filename, XMKeyProvider())
    elif action == 'xmencrypt':
        filename = _get_arg(sys.argv, 2, None)
        out_filename = _get_arg(sys.argv, 3, None)
        key_id = _get_arg(sys.argv, 4, None)
        if filename and out_filename and key_id:
            done = True
            _create_directory_if(os.path.dirname(out_filename))
            success = _encrypt(filename, out_filename, key_id, XMKeyProvider())
            print('Done' if success else 'FAILED')
    elif action == 'xmdecrypt':
        filename = _get_arg(sys.argv, 2, None)
        out_filename = _get_arg(sys.argv, 3, None)
        if filename and out_filename:
            done = True
            _create_directory_if(os.path.dirname(out_filename))
            success = _decrypt(filename, out_filename, XMKeyProvider())
            print('Done' if success else 'FAILED')
    elif action == 'xmencrypt-key':
        key_id = _get_arg(sys.argv, 2, None)
        base64_encoded_key = _get_arg(sys.argv, 3, None)
        if key_id and base64_encoded_key:
            done = True
            try:
                key = _base64_decode_key(base64_encoded_key)
                key_filename = _encrypt_key_file(key_id, key, XMKeyProvider())
                print(key_id + ': saved encrypted with the MasterKey in ' + key_filename)
            except Exception as ex:
                print(key_id + ': *** ERROR ****', ex)
    elif action == 'xmdecrypt-key':
        key_id = _get_arg(sys.argv, 2, None)
        if key_id:
            done = True
            key_provider = XMKeyProvider()
            key = key_provider.get_key(key_id)
            if key:
                print(base64.b64encode(key).decode())
            else:
                print('Key Id:', key_id, '*** NOT FOUND ***')
    elif action == 'xmencrypt-mediastore':
        store = _get_arg(sys.argv, 2, '').lower()
        sending = store == 'sendingfaxqueue' or store == 'sendingandreceivingfaxqueues'
        receiving = store == 'receivingfaxqueue' or store == 'sendingandreceivingfaxqueues'
        sub_store = _get_arg(sys.argv, 3, '')
        if (sending or receiving) and sub_store:
            done = True
            if sub_store.lower() == 'all':
                sub_store = None
            backup_folder = _get_arg(sys.argv, 4, None)
            with LogFile(open_log_file('xmencrypt-mediastore')) as log_file:
                _encrypt_mediastores(sending, receiving, sub_store, backup_folder, XMKeyProvider(), log_file, reencrypt=False)
    elif action == 'xmreencrypt-mediastore':
        store = _get_arg(sys.argv, 2, '').lower()
        sending = store == 'sendingfaxqueue' or store == 'sendingandreceivingfaxqueues'
        receiving = store == 'receivingfaxqueue' or store == 'sendingandreceivingfaxqueues'
        sub_store = _get_arg(sys.argv, 3, '')
        if (sending or receiving) and sub_store:
            done = True
            if sub_store.lower() == 'all':
                sub_store = None
            backup_folder = _get_arg(sys.argv, 4, None)
            with LogFile(open_log_file('xmreencrypt-mediastore')) as log_file:
                _encrypt_mediastores(sending, receiving, sub_store, backup_folder, XMKeyProvider(), log_file, reencrypt=True)
    elif action == 'xmdecrypt-mediastore':
        store = _get_arg(sys.argv, 2, '').lower()
        sending = store == 'sendingfaxqueue' or store == 'sendingandreceivingfaxqueues'
        receiving = store == 'receivingfaxqueue' or store == 'sendingandreceivingfaxqueues'
        sub_store = _get_arg(sys.argv, 3, '')
        if (sending or receiving) and sub_store:
            done = True
            if sub_store.lower() == 'all':
                sub_store = None
            backup_folder = _get_arg(sys.argv, 4, None)
            with LogFile(open_log_file('xmdecrypt-mediastore')) as log_file:
                _decrypt_mediastores(sending, receiving, sub_store, backup_folder, XMKeyProvider(), log_file)
    elif action == 'xmchange-mediastore-master-key':
        base64_encoded_master_key = _get_arg(sys.argv, 2, None)
        new_base64_encoded_master_key = _get_arg(sys.argv, 3, None)
        new_master_key_id = _get_arg(sys.argv, 4, None)
        if base64_encoded_master_key and new_base64_encoded_master_key and new_master_key_id:
            done = True
            backup_folder = _get_arg(sys.argv, 5, None)
            master_key = _base64_decode_key(base64_encoded_master_key)
            new_master_key = _base64_decode_key(new_base64_encoded_master_key)
            with LogFile(open_log_file('xmchange-mediastore-master-key')) as log_file:
                _change_mediastore_master_key(backup_folder, master_key, new_master_key, new_master_key_id, XMKeyProvider(), log_file)
    elif action == 'xmbackup-keys':
        backup_folder = _get_arg(sys.argv, 2, None)
        timestamp = _get_arg(sys.argv, 3, None)
        if backup_folder and (not timestamp or timestamp.lower() == 'timestamp'):
            done = True
            backup_ext = None if not timestamp else datetime.datetime.now().strftime(".%Y%m%d%H%M%S")
            with LogFile(open_log_file('xmbackup-keys')) as log_file:
                _backup_keys(backup_folder, backup_ext, XMKeyProvider(), log_file)
    elif action == 'xmbackup-master-key':
        backup_folder = _get_arg(sys.argv, 2, None)
        timestamp = _get_arg(sys.argv, 3, None)
        if backup_folder and (not timestamp or timestamp.lower() == 'timestamp'):
            done = True
            backup_ext = None if not timestamp else datetime.datetime.now().strftime(".%Y%m%d%H%M%S")
            _backup_master_key(backup_folder, backup_ext, XMKeyProvider())
    elif action == 'create-key':
        done = True
        print(base64.b64encode(gen_random_key_256()).decode())

    if not done:
        print('')
        print('  Usage:')
        print('')
        print('    Operations on files:')
        print('        describe filename')
        print('        encrypt filename out-filename key-id base64-encoded-key')
        print('        decrypt filename out-filename base64-encoded-key')
        print('        decrypt-key key-filename base64-encoded-master-key')
        print('    Operations on files and mediastore on the fax server:')
        print('        xmconfig')
        print('        xmdescribe filename')
        print('        xmencrypt filename out-filename key-id')
        print('        xmdecrypt filename out-filename')
        print('        xmencrypt-key key-id base64-encoded-key')
        print('        xmdecrypt-key key-id')
        print('        xmencrypt-mediastore {SendingFaxQueue|ReceivingFaxQueue|SendingAndReceivingFaxQueues} {All|sub-store} [backup-folder]')
        print('        xmreencrypt-mediastore {SendingFaxQueue|ReceivingFaxQueue|SendingAndReceivingFaxQueues} {All|sub-store} [backup-folder]')
        print('        xmdecrypt-mediastore {SendingFaxQueue|ReceivingFaxQueue|SendingAndReceivingFaxQueues} {All|sub-store} [backup-folder]')
        print('        xmchange-mediastore-master-key base64-encoded-master-key new-base64-encoded-master-key new-master-key-id [backup-folder]')
        print('        xmbackup-keys backup-folder [timestamp]')
        print('        xmbackup-master-key backup-folder [timestamp]')
        print('    Other operations:')
        print('        create-key')

if __name__ == "__main__":
    try:
        _main()
    except Exception as ex:
        print('*** ERROR ***:', ex)
