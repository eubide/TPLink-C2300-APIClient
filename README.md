# TP-Link Archer API client

Python client for the LuCI HTTP API on official TP-Link Archer firmware. It implements the login handshake (RSA-encrypted password and signature) and the end-to-end AES encryption the web UI uses, so requests can be sent the same way the router's own admin page sends them.

## Compatible (tested) versions

| Hardware | Firmware |
|---|---|
| Archer AX6000 v1.0 | 1.4.3 Build 20250725 rel.18118(4555) |
| Archer AX6000 v1.0 | 1.3.0 Build 20221208 rel.45145(5553) |
| Archer C2300 v2.0 | 1.1.1 Build 20200918 rel.67850(4555) |

## Installation

The client is a single file, `tplink.py`. It depends on `requests` and `pycryptodome`:

```
pip install requests pycryptodome
```

## Usage

```python
import json
import logging
import tplink

api = tplink.TPLinkClient('192.168.1.1', log_level = logging.ERROR)

# logout_others = True kicks out anyone logged in to the admin page
api.connect('password', logout_others = False)

try:
    print(json.dumps(api.get_client_list(), indent = 4, sort_keys = True))

    api.block_device('7D-24-92-59-70-E8')
    api.unblock_device('7D-24-92-59-70-E8')

    api.block_domain('Kids', 'example.com')
finally:
    # the router allows a single admin session, so always log out
    api.logout()
```

## API

All methods except `connect` and `logout` return the router's decrypted JSON response, usually `{'success': True, 'data': ...}`.

### Session

| Method | Description |
|---|---|
| `TPLinkClient(host, log_level = logging.INFO, timeout = 10)` | `timeout` is in seconds and applies to every request |
| `connect(password, logout_others = False)` | Logs in as `admin`. Raises `UserConflictException` if another admin session is open and `logout_others` is `False` |
| `logout()` | Ends the session. Returns `True` on success |

### Clients and LEDs

| Method | Description |
|---|---|
| `get_client_list()` | Connected wired and wireless clients |
| `get_led_status()` | LED state |
| `set_led_status(status)` | For example `'toggle'` |

### Access control (block a whole device)

| Method | Description |
|---|---|
| `get_black_devices()` | Devices that can be blocked |
| `get_black_list()` | Devices currently blocked |
| `block_device(mac)` | Blocks all traffic from a device |
| `unblock_device(mac)` | Raises `ValueError` if the device is not blocked |

MAC addresses are accepted in any case, with `-` or `:` separators.

### Parental controls (block a website)

| Method | Description |
|---|---|
| `get_parental_profiles()` | Profiles with their devices, filters and blocked websites |
| `block_domain(profile_name, domain)` | Adds a domain to the profile's blocked websites |
| `unblock_domain(profile_name, domain)` | Removes a domain from the profile's blocked websites |

Both domain methods raise `ValueError` if the profile does not exist. Domains are compared case-insensitively, and nothing is sent to the router when the list would not change.

Things to know about how the firmware filters websites:

* Blocking applies to every device in the profile. To block a domain on a single device, put that device in a profile of its own.
* The profile's other settings (time limits, bedtime, filter level) are sent back unchanged, but the web UI also sends `app_list`, `bedtime` and `time_limit`, which the client does not read. This has been tested on profiles with no bedtime or time limit.
* Devices that use a private (randomized) Wi-Fi address show up with a new MAC and fall outside their profile. Turn the private address off for that network on devices that must stay filtered.

## Errors

| Exception | When |
|---|---|
| `LoginException` | Wrong password or too many attempts |
| `UserConflictException` | Another admin session is open (subclass of `LoginException`) |
| `tplink.ApiException` | Called before `connect()`, non-200 HTTP response, or a failed read inside a method that needs its data |
| `ValueError` | Unknown parental control profile, or device not in the block list |
| `requests.exceptions.Timeout` | The router did not answer within `timeout` seconds |

## Router responses to the login request

* Wrong password

  `{'errorcode': 'login failed', 'success': False, 'data': {'failureCount': 1, 'errorcode': '-5002', 'attemptsAllowed': 9}}`

* Exceeded max auth attempts (usually 10)

  `{'errorcode': 'exceeded max attempts', 'success': False, 'data': {'failureCount': 10, 'attemptsAllowed': 0}}`

* Another user is logged in

  `{'errorcode': 'user conflict', 'success': False, 'data': {}}`

* Successful auth

  `{'success': True, 'data': {'stok': '94640fd8887fb5750d6a426345581b87'}}`

The `stok` is the session token and grants admin access until logout. The client does not log it.

## Discovering endpoints

`endpoints.txt` lists the endpoints and forms found in the web UI. Most of them answer to `{'operation': 'read'}`, some only to `{'operation': 'load'}`. To see what the web UI sends for a write, log in to the admin page, open the browser console, and wrap the UI's encryption function so it logs each request before it is encrypted:

```javascript
(function () {
  var proto = jQuery.encrypt.AES.prototype, encrypt = proto.encrypt;
  proto.encrypt = function (plain) {
    if (!/operation=(read|load)/.test(plain)) console.log(decodeURIComponent(plain));
    return encrypt.apply(this, arguments);
  };
})();
```

Then make the change in the web UI and copy the logged request.

___

Licensed under GNU GPL v3
