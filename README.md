Bet game API
============

Endpoints
---------

### POST /players
Player registration.

*Arguments:*

 * `player_nick` - required, should match the one used on EA Games
 * `email` - required?
 * `password`
 * `facebook_token` - optional
 * `push_token` - device identifier for push notifications - only for login-related methods
 * maybe more...

Returns object with Player resource and auth token. Returns `201` HTTP code.
```json
{
	"player": {Player resource},
	"token": "authentication token"
}
```

### GET /players
Retrieve list of players. Not implemented.

### GET /players/<id>
Retrieve given player's data.

ID may be either integer internal ID, player's nick or `me`.

For the player requesting will return whole info;
for other players will only return Limited Player resource.

### PATCH /players/<id>
Update player's data.
Accepts any of not-login-related arguments of `POST /players`.

ID may be either integer internal ID, player's nick or `me`.

Returns Player resource.


### POST /players/login
Receive a login token.

*Arguments*:

 * `email`
 * `player_nick` (can be specified instead of email)
 * `password`
 * `push_token` of the current device


### GET /balance
Learn current balance


### POST /balance/append
Buy internal coins for real money


### POST /balance/withdraw
Sell internal coins for real money


### POST /games
Create game invitation


### GET /games
Retrieve games (both accepted and not accepted yet) available for current player -
i.e. either initiated by or sent to them.


### PATCH /games
Accept or decline an invitaton.


Resources
---------

### Player resource
```json
{
	"id": 23, // internal identifier
	"player_nick": "DERP HACKER",
	"email": "user@name.org",
	"facebook_connected": true, // boolean
	"balance": 135.2, // in coins
	"devices": [ list of Device resources ],
	... // some stats will be added
}
```

### Limited Player resource
Returned if you want to get info about other players.
Doesn't include sensitive information like `balance` or `devices`.
```json
{
	"id": 23, // internal identifier
	"player_nick": "DERP HACKER",
	"email": "user@name.org",
	"facebook_connected": true, // boolean
	... // some stats
}
```

### Device resource
```json
{
	"id": 10, // internal id
	"last_login": "some date"
}
```
