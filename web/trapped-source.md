
## Trapped Source :: Very Easy

#### Scenario

```
The Intergalactic Ministry of Spies tested Pandora's movement and intelligence abilities.
She found herself locked in a room with no apparent means of escape. 
Her task was to unlock the door and make her way out. 
Can you help her in opening the door?
```

#### Solve

This challenges present a **PIN pad** to you and you have to enter the correct PIN to get the flag.

When you look at what the event does when you submit a PIN, you understand that the validation happens on the client side.

This means that the correct PIN is contained in the sources, since it does not communicate with a backend to validate the it.

While analyzing the source, I found that it was possible to obtain the PIN by writing the following in the Javascript console.

```javascript
console.log(CONFIG.correctPin)
```

This is the variable that our ping is compared to.
Once we enter the returned PIN, we obtain the flag.

```
HTB{V13w_50urc3_c4n_b3_u53ful!!!}
```


