Bet game API
============

Authorization
-------------
Most API endpoints require authorization.
(In fact, the only ones not requiring it are user registration and login.)
For authorization you should include an auth token with your request.
That token can be included with any of the following ways:

 * Add an `Authorization` header with value of `Bearer your.token.here`
 * Add a `token` parameter to the request.

Token can be obtained either when registering new user (`POST /players`)
or with dedicated login method (`POST /players/login`).
Token is valid for one year, but can be invalidated by changing password.

Parameters for endpoints can be passed either as GET arguments, as POST form data
or in a JSON object (with corresponding content-type).

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
for other players will only return *Limited Player resource*.

### PATCH /players/<id>
Update player's data.
Accepts any of not-login-related arguments of `POST /players`.

ID may be either integer internal ID, player's nick or `me`.

Returns Player resource.


### POST /players/<nick>/login
Receive a login token.

In url you can include either `player_nick` or email address.

*Arguments*:

 * `password`
 * `push_token` of the current device


### GET /balance
Learn current player's balance.

Arguments: none

Result:
```json
{
	"balance": { Balance resource }
}
```


### POST /balance/deposit
Buy internal coins for real money.
You should use [https://github.com/paypal/PayPal-iOS-SDK](PayPal SDK for iOS) or similar.

Arguments:

 * `currency`
 * `total` (value in that currency)
 * `transaction_id` (for real transactions)
 * `dry_run` - set to True and omit `transaction_id` if you want to just determine current exchange rate.

Returns:
```json
{
	"success": true,
	"dry_run": false,
	"added": 25, // in coins
	"balance": { Balance object }
}
```


### POST /balance/withdraw
Sell internal coins for real money.

Arguments:

 * `paypal_email`: email of paypal account which should receive coins
 * `coins`: how many coins do you want to sell
 * `currency`: which currency do you want to get as a result
 * `dry_run`: optional; if set to True, don't actually transfer coins but only return rate etc

Result:
```json
{
	"success": true, // boolean
	"paid": {
		"currency": "USD",
		"value": 10.5,
	},
	"dry_run": false,
	"transaction_id": "Transaction Identifier",
	"balance": { Balance resource }
}
```


### POST /games
Create game invitation.

Arguments:

 * `opponent_id`: either player nick or internal numeric id of opponent.
 * `gamemode`: one of game modes - `fifaSeasons`, `futSeasons`, `fut`, `friendlies` or `coop`.
 * `gametype`: either `xboxone-fifa14` or `xboxone-fifa15`.
 * `bet`: numeric bet amount, should not exceed your balance.

When creating an invitation, corresponding amount of coins is immediately locked on user's account.
These coins will be released when invitation is declined
or when the game finishes with either win or draw of creator.

Returns *Game resource* on success.

### GET /games
Retrieve games (both accepted and not accepted yet) available for current player -
i.e. either initiated by or sent to them.

This request supports pagination:

 * `page`: page to return (defaults to 1)
 * `results_per_page`: how many games to include per page (defaults to 10, max is 50)

Return:
```json
{
	"games": [
		list of Game resource objects
	],
	"page": 1 // current page
	"total_pages": 9,
	"num_results": 83, // total count
}
```


### GET /games/<id>
Returns details on particular game based on its ID.
Will not return data on games not related to current user.

Return: Game resource


### PATCH /games/<id>
Accept or decline an invitaton.

Arguments possible:

 * `state`: either `accepted` or `declined`

Accepting game will immediately lock corresponding amount on player's balance
and the game will be considered started.

If trying to accept and there is no coins enough to cover game's bet amount,
this request will fail with `400` code and additional `problem` field with value `coins`.
In such situation the user should be advised to buy more coins.

Returns *Game resource* object on success.


Resources
---------

### Player resource
```json
{
	"id": 23, // internal identifier
	"player_nick": "DERP HACKER",
	"email": "user@name.org",
	"facebook_connected": true, // boolean
	"devices": [ list of Device resources ],
	"balance": { Balance resource },
	... // some stats will be added
}
```

### Balance resource
```json
{
	"full": 135.2, // how many coins are there
	"locked": 10, // locked coins are ones placed on the table for some active games
	"available": 125.2, // how many coins can you freely use or withdraw - this is full minus locked
}
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

### Game resource
Possible game states:

 * `new`: this game is in invitation phase
 * `declined`: opponent declined an offer
 * `accepted`: opponent accepted an offer and game is considered ongoing, system polls EA servers for result
 * `finished`: system got game outcome from EA servers and already moved bets accordingly

```json
{
	"id": 15, // internal id
	"creator": { Limited Player resource },
	"opponent": { Limited Player resource },
	"gamemode": "friendlies", // or any other, see POST /games for details
	"gametype": "xboxone-fifa15", // see POST /games for options
	"bet": 5.29, // bet amount
	"create_date": "RFC datetime",
	"state": "finished", // see above
	"accept_date": "RFC datetime", // date of eiter accepting or declining game, null for new games
	"winner": "opponent", // either "creator", "opponent" or "draw"
	"finish_date": "RFC datetime" // date when this game was finished, according to EA servers
}
```
