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
 * `push_token` - device identifier for push notifications
 * maybe more...

Returns Player resource and `201` HTTP code.
Also probably returns login token.


### PATCH /players
Update player's data.


### POST /players/login
Receive a login token.

*Arguments*:

 * `email`
 * `player_nick` (can be specified instead of email)
 * `password`
 * `push_token`


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
	...
}
```
