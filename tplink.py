'''
TP-Link Archer C2300 API client v1.1.0

Compatible (tested) with versions:
  Firmware: 1.1.1 Build 20200918 rel.67850(4555)
  Hardware: Archer C2300 v2.0

Copyright (c) 2021 Michal Chvila <dev@electry.sk>.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
'''
import requests
import json
import re
import binascii
import secrets
import logging
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import MD5
from base64 import b64encode, b64decode

import urllib.parse

class LoginException(Exception):
    pass

class UserConflictException(LoginException):
    pass

class ApiException(Exception):
    pass

class TPLinkClient:
    HEADERS = {
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
    }

    def __init__(self, host, log_level = logging.INFO, timeout = 10):
        logging.basicConfig()
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)
        self.req = requests.Session()

        self.host = host
        self.timeout = timeout
        self.token = None

        self.rsa_key_pw = None
        self.rsa_key_auth = None

        self.md5_hash_pw = None
        self.aes_key = None

    def get_url(self, endpoint, form):
        stok = self.token if self.token is not None else ''
        return 'http://{}/cgi-bin/luci/;stok={}/{}?form={}'.format(self.host, stok, endpoint, form)

    def connect(self, password, logout_others = False):
        # the key requests must not carry the stok of a previous session
        self.token = None

        # hash the password
        self.md5_hash_pw = self.__hash_pw('admin', password)

        # request public RSA keys from the router
        self.rsa_key_pw = self.__req_rsa_key_password()
        self.rsa_key_auth = self.__req_rsa_key_auth()

        # generate AES key
        self.aes_key = self.__gen_aes_key()

        # encrypt the password
        encrypted_pw = self.__encrypt_pw(password)

        # authenticate
        try:
            self.token = self.__req_login(encrypted_pw)
        except UserConflictException as e:
            if logout_others:
                self.token = self.__req_login(encrypted_pw, True)
            else:
                raise e

    def logout(self):
        if self.token is None:
            return False

        try:
            return self.__req_logout()
        finally:
            self.token = None

    def get_client_list(self):
        url = self.get_url('admin/status', 'client_status')
        data = {
            'operation': 'read'
        }

        return self.__request(url, data, encrypt = True)
    
## CUSTOM FUNCTIONS ## JASON GRIMARD 3/13/2023
    
    # This function returns the status of the router LEDs
    def get_led_status(self):
        url = self.get_url('admin/ledgeneral', 'setting')
        data = {
            'operation': 'read'
        }

        return self.__request(url, data, encrypt = True)
    
    # This function toggles the status of the router LEDs
    def set_led_status(self, status):
        url = self.get_url('admin/ledgeneral', 'setting')
        data = {
            'operation': 'write',
            'led_status': status
        }

        return self.__request(url, data, encrypt = True)
    
    # This function lists the devices that are available to block
    def get_black_devices(self):
        url = self.get_url('admin/access_control', 'black_devices')
        data = {
            'operation': 'load'
        }

        return self.__request(url, data, encrypt = True)
    
    # This function lists the devices that are currently blocked
    def get_black_list(self):
        url = self.get_url('admin/access_control', 'black_list')
        data = {
            'operation': 'load'
        }

        return self.__request(url, data, encrypt = True)
    

    # This function blocks a device by MAC address
    def block_device(self, mac):
        url = self.get_url('admin/access_control', 'black_devices')
        device_data = {
                "mac":self.__normalize_mac(mac),
                "host":"NOT HOST"
        }
        data = {
            'operation': 'block',
            'key': 'key=1', # not sure if a key is really needed
            'index': 0,
            # the router expects a JSON list
            'data': f"[{json.dumps(device_data)}]"
        }

        return self.__request(url, data, encrypt = True)

    # This function unblocks a device by MAC address
    def unblock_device(self, mac):
        url = self.get_url('admin/access_control', 'black_list')
        blocked_devices = self.__check_success(self.get_black_list())
        mac = self.__normalize_mac(mac)
        match = next(((i, d) for i, d in enumerate(blocked_devices['data']) if self.__normalize_mac(d['mac']) == mac), None)
        if match is None:
            raise ValueError('Device not found in black list: {}'.format(mac))
        index, device = match
        data = {
            'key': device.get('key', 'anything'), # not sure if a key is really needed
            'index': str(index),
            'operation': 'remove'
        }

        return self.__request(url, data, encrypt = True)

    def __normalize_mac(self, mac):
        # the router stores MACs as AA-BB-CC-DD-EE-FF
        return mac.strip().upper().replace(':', '-')

    def get_parental_profiles(self):
        url = self.get_url('admin/smart_network', 'patrol_owner_list')
        data = {
            'operation': 'read'
        }

        return self.__request(url, data, encrypt = True)

    # The router filters websites per profile, so this affects every device in the profile
    def block_domain(self, profile_name, domain):
        domain = domain.strip().lower()
        return self.__update_website_list(profile_name, lambda websites: websites if domain in [w.lower() for w in websites] else websites + [domain])

    def unblock_domain(self, profile_name, domain):
        domain = domain.strip().lower()
        return self.__update_website_list(profile_name, lambda websites: [w for w in websites if w.lower() != domain])

    def __update_website_list(self, profile_name, change):
        profiles = self.__check_success(self.get_parental_profiles())['data']
        profile = next((p for p in profiles if p['name'] == profile_name), None)
        if profile is None:
            raise ValueError('Parental control profile not found: {}'.format(profile_name))

        # the router returns empty lists as {} but the web UI sends them back as []
        old = dict(profile)
        for field in ('categories_list', 'website_list'):
            if old[field] == {}:
                old[field] = []
        old.pop('insights', None)
        old['client_list'] = [{k: v for k, v in c.items() if k != 'online'} for c in old['client_list']]

        new = dict(old)
        new['website_list'] = change(old['website_list'])
        if new['website_list'] == old['website_list']:
            return {'success': True, 'data': profiles}

        url = self.get_url('admin/smart_network', 'patrol_owner_list')
        data = {
            'key': old['key'],
            'new': json.dumps(new, separators = (',', ':'), ensure_ascii = False),
            'old': json.dumps(old, separators = (',', ':'), ensure_ascii = False),
            'operation': 'update'
        }

        return self.__request(url, data, encrypt = True)


## END CUSTOM FUNCTIONS ##

    def __request(self, url, data, encrypt = False, is_login = False):
        if encrypt:
            if self.aes_key is None:
                raise ApiException('Not connected, call connect() first')

            data_str = self.__format_body_to_encrypt(data)

            # pad to a multiple of 16 with pkcs7
            data_padded = pad(data_str.encode('utf8'), 16, 'pkcs7')

            # encrypt the body
            aes_encryptor = self.__gen_aes_cipher(self.aes_key)
            encrypted_data_bytes = aes_encryptor.encrypt(data_padded)

            # encode encrypted binary data to base64
            encrypted_data = b64encode(encrypted_data_bytes).decode('utf8')

            # get encrypted signature
            signature = self.__get_signature(len(encrypted_data), is_login)

            # order matters here! signature needs to go first (or we get empty 403 response)
            form_data = {
                'sign': signature,
                'data': encrypted_data
            }
        else:
            form_data = data

        r = self.req.post(url, data = form_data, headers = self.HEADERS, timeout = self.timeout)

        safe_url = re.sub(r';stok=[^/]*', ';stok=<redacted>', r.url)
        self.logger.debug('<Request  {}>'.format(safe_url))
        self.logger.debug(r)
        self.logger.debug(r.text)

        if r.status_code != 200 or r.text == '':
            # an empty 403 usually means the signature was rejected or the session expired
            raise ApiException('HTTP {} with {} body from {}'.format(r.status_code, 'empty' if r.text == '' else 'non-empty', safe_url))

        if not encrypt:
            return json.loads(r.text)

        try:
            envelope = json.loads(r.text)
        except json.decoder.JSONDecodeError:
            # some endpoints answer with the bare base64 ciphertext instead of {"data": ...}
            envelope = None

        if envelope is None:
            plaintext = self.__decrypt(r.text)
        elif 'data' in envelope:
            plaintext = self.__decrypt(envelope['data'])
        else:
            # unencrypted error, e.g. {"errorcode": "timeout", "success": false} on an expired session
            return envelope

        try:
            return json.loads(plaintext)
        except json.decoder.JSONDecodeError:
            return plaintext

    def __decrypt(self, b64_data):
        aes_decryptor = self.__gen_aes_cipher(self.aes_key)
        response = aes_decryptor.decrypt(b64decode(b64_data))

        return unpad(response, 16, 'pkcs7').decode('utf8')

    def __check_success(self, response):
        if not isinstance(response, dict) or response.get('success') is not True:
            raise ApiException('Router request failed: {}'.format(response))

        return response

    def __format_body_to_encrypt(self, data):
        return urllib.parse.urlencode(data)

    def __hash_pw(self, arg1, arg2 = None):
        md5 = MD5.new()

        if arg2 is not None:
            md5.update((arg1 + arg2).encode('utf8'))
        else:
            md5.update(arg1.encode('utf8'))

        result = md5.hexdigest()
        assert len(result) == 32

        return result

    def __encrypt_pw(self, password):
        '''
        pkcs1pad2 - PKCS#1 (type 2, random) pad input string s to n bytes
        '''
        pub_key = self.__make_rsa_pub_key(self.rsa_key_pw)
        rsa = PKCS1_v1_5.new(pub_key)

        binpw = password.encode('utf8')

        encrypted = rsa.encrypt(binpw)
        as_string = binascii.hexlify(encrypted).decode('utf8')

        assert len(as_string) == 256
        assert len(as_string) == (len(hex(pub_key.n)) - 2)

        return as_string

    def __make_rsa_pub_key(self, key):
        n = int('0x' + key[0], 16)
        e = int('0x' + key[1], 16)
        return RSA.construct((n, e))

    def __gen_aes_key(self):
        KEY_LEN = 128 // 8
        IV_LEN = 16

        # the web UI also uses decimal digits only
        key = ''.join(secrets.choice('0123456789') for _ in range(KEY_LEN))
        iv = ''.join(secrets.choice('0123456789') for _ in range(IV_LEN))

        assert len(key) == 16
        assert len(iv) == 16

        return (key, iv)

    def __gen_aes_cipher(self, aes_key):
        key, iv = aes_key

        # CBC mode, PKCS7 padding
        return AES.new(key.encode('utf8'), AES.MODE_CBC, iv = iv.encode('utf8'))

    def __get_signature(self, body_data_len, is_login = False):
        '''
        aes_key:       generated pseudo-random AES key (CBC, PKCS7)
        rsa_auth_key:  RSA public key from the TP-Link API endpoint (login?form=auth)
        auth_md5_hash: MD5 hash of the username+password as string
        body_data_len: length of the encrypted body message
        is_login:      set to True for login request
        '''
        rsa_n, rsa_e, rsa_seq = self.rsa_key_auth

        if is_login:
            # on login we also send our AES key, which is subsequently
            # used for E2E encrypted communication
            aes_key, aes_iv = self.aes_key
            aes_key_string = 'k={}&i={}'.format(aes_key, aes_iv)

            sign_data = '{}&h={}&s={}'.format(aes_key_string, self.md5_hash_pw, rsa_seq + body_data_len)
        else:
            sign_data = 'h={}&s={}'.format(self.md5_hash_pw, rsa_seq + body_data_len)

        signature = ''
        pos = 0

        # encrypt the signature using the RSA auth public key
        rsa = PKCS1_v1_5.new(self.__make_rsa_pub_key(self.rsa_key_auth))

        while pos < len(sign_data):
            enc = rsa.encrypt(sign_data[pos : pos+53].encode('utf8'))

            signature += binascii.hexlify(enc).decode('utf8')
            pos = pos + 53

        return signature

    def __req_rsa_key_password(self):
        '''
        Return value:
            (n, e) RSA public key for encrypting the password
        '''
        url = self.get_url('login', 'keys')
        data = {
            'operation': 'read'
        }

        response = self.__request(url, data, encrypt = False)
        assert response['success'] == True

        pw_pub_key = response['data']['password']
        assert len(pw_pub_key[0]) == 256
        assert len(pw_pub_key[1]) == 6

        return (pw_pub_key[0], pw_pub_key[1])

    def __req_rsa_key_auth(self):
        '''
        Return value:
            (n, e, seq) RSA public key for encrypting the signature
        '''
        url = self.get_url('login', 'auth')
        data = {
            'operation': 'read'
        }

        response = self.__request(url, data, encrypt = False)
        assert response['success'] == True

        auth_pub_key = response['data']['key']
        assert len(auth_pub_key[0]) == 128
        assert len(auth_pub_key[1]) == 6

        return (auth_pub_key[0], auth_pub_key[1], response['data']['seq'])

    def __req_login(self, encrypted_pw, force_login = False):
        '''
        Return value (on successful login):
            stok - API auth token
        '''
        url = self.get_url('login', 'login')
        data = {
            'operation': 'login',
            'password': encrypted_pw
        }

        if force_login:
            data['confirm'] = 'true'

        response = self.__request(url, data, encrypt = True, is_login = True)
        # on success data holds the stok, which grants admin access
        self.logger.info(response if response.get('success') is False else {'success': response.get('success')})

        assert 'success' in response

        if response['success'] is False:
            assert 'errorcode' in response

            if response['errorcode'] == 'login failed':
                attempts_allowed = response['data']['attemptsAllowed']
                attempts_total = response['data']['failureCount'] + attempts_allowed

                raise LoginException('Login failed, wrong password. Remaining attempts: {}/{}'.format(attempts_allowed, attempts_total))
            elif response['errorcode'] == 'exceeded max attempts':
                raise LoginException('Login failed, maximum login attempts exceeded. Please wait for 60-120 minutes.')
            elif response['errorcode'] == 'user conflict':
                raise UserConflictException('Login conflict. Someone else is logged in.')
            else:
                raise LoginException(response)

        assert response['success'] == True

        '''
        Example responses:

        {'errorcode': 'login failed', 'success': False, 'data': {'failureCount': 1, 'errorcode': '-5002', 'attemptsAllowed': 9}}

        {'errorcode': 'exceeded max attempts', 'success': False, 'data': {'failureCount': 10, 'attemptsAllowed': 0}}

        {'errorcode': 'user conflict', 'success': False, 'data': {}}

        {'success': True, 'data': {'stok': '94640fd8887fb5750d6a426345581b87'}}
        '''

        return response['data']['stok']

    def __req_logout(self):
        assert self.token is not None

        url = self.get_url('admin/system', 'logout')
        data = {
            'operation': 'write'
        }

        response = self.__request(url, data, encrypt = True)
        self.logger.info(response)

        return isinstance(response, dict) and response.get('success') is True
