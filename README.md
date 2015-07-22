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
For all player-related endpoints which include nickname/id in url,
you can use `_` instead of nickname
and add `id` parameter (either in GET-style or POST-style) containing that value.
This might help with some libraries which fail with urls containing spaces and special characters.

Also you can use `me` alias which means «player currently logged in».

### POST /players
Player registration.

*Arguments:*

 * `nickname` - required
 * `email` - required
 * `password`
 * `facebook_token` - optional
 * `ea_gamertag` - optional, should match the one used on EA Games
 * `push_token` - device identifier for push notifications - only for login-related methods
 * maybe more...

 * `_force`: force registration with invalid gamertag (effectively disables gamertag validation). Should not be used for production.

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
If you provide `password` field, you should also provide `old_password` field
which will be validated against user's current password.
Although it is not required if user has no password configured
(i.e. if he was registered with Facebook).

ID may be either integer internal ID, player's nick or `me`.

Returns Player resource.


### POST /players/<nick>/login
Receive a login token.

In url you can include either `nickname`, `ea_gamertag` or email address.

*Arguments*:

 * `password`
 * `push_token` of the current device

### POST /federated_login
Federated login via Facebook.

*Arguments*:

 * `token`: Facebook auth token

Token should be requested with `email` permission for server to be able to fetch user's email.

This endpoint returns object identical to `POST /players` or `POST /players/<nick>/login`,
depending on whether this player was already registered or not.
HTTP code will be `201` or `200`, accordingly.

### POST /players/<nick>/reset_password
Initiate password recovery.
Will send password changing link to user's registered email.
User can be identified by either gamertag or email address.

*Arguments*: none.

*Result*:
```json
{
	"success": true, // or false if some error occurs
	"message": "Descripting message" // probably error description
}
```


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


### GET /gametypes
List available game types.
For now, there are only 2 of them: `fifa14-xboxone` and `fifa15-xboxone`.

***NOTICE: this endpoint's return format might change later***

```json
{
	"gametypes": [
		"fifa14-xboxone",
		"fifa15-xboxone
	]
}
```

### GET /gametypes/<type>/image
Retrieves a picture for given game type.

Arguments:

 * `w`: image width (defaults to maximum possible)
 * `h`: image width (defaults to maximum possible)

If only one of arguments is provided, other will be chosen to maintain aspect ratio.
If both are provided, image will be cut to keep aspect ratio.

Returns image itself with corresponding MIME type (most likely PNG).


### POST /games
Create game invitation.

Arguments:

 * `opponent_id`: either nickname, gamertag or internal numeric id of opponent.
 * `gamertag_creator`: gamertag of the player for which invitation creator roots.
	Optional, defaults to creator's own gamertag (if specified).
 * `gamertag_opponent`: gamertag of the player for which invitation opponent roots.
	Optional, defaults to opponent's own gamertag (if specified).
 * `gametype`: either `fifa14-xboxone` or `fifa15-xboxone`.
 * `gamemode`: one of game modes - `fifaSeasons`, `futSeasons`, `fut`, `friendlies` or `coop`.
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
	"nickname": "John Smith",
	"email": "user@name.org",
	"facebook_connected": true, // boolean
	"ea_gamertag": "DERP HACKER",
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
```

### Limited Player resource
Returned if you want to get info about other players.
Doesn't include sensitive information like `balance` or `devices`.
```json
{
	"id": 23, // internal identifier
	"nickname": "John Smith",
	"email": "user@name.org",
	"facebook_connected": true, // boolean
	"ea_gamertag": "DERP HACKER",
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
	"gamertag_creator": "Creator Gamer Tag",
	"gamertag_opponent": "Opponent Gamer Tag",
	"gametype": "xboxone-fifa15", // see POST /games for options
	"gamemode": "friendlies", // or any other, see POST /games for details
	"bet": 5.29, // bet amount
	"create_date": "RFC datetime",
	"state": "finished", // see above
	"accept_date": "RFC datetime", // date of eiter accepting or declining game, null for new games
	"winner": "opponent", // either "creator", "opponent" or "draw"
	"finish_date": "RFC datetime" // date when this game was finished, according to EA servers
}
```
