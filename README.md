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

### Workflow guide
Here is a list of endpoints which will be called in typical user's workflow.
It might differ somewhat from what you have in designs,
but should cover all existing endpoints,
so it should be easy to adapt it to design.

* User first installed an app.
  App asks him if he want to register as a new user, login, or register/login with Facebook.
    + If user chooses plain registration, you should ask him to enter
      nickname, email, password
      and optionally EA gamertag.
      Then you call `POST /players` endpoint
      passing the data you got from user
      and this device's push token.
    + If user chose to log in, you will ask to enter name
      (which can be either email, nickname or gamertag) and password.
      Then you call `POST /players/<name entered by user>/login`
      passing password and device's push token.
      **As an alternative**, if your SDK doesn't allow
      whitespaces and special characters in URL,
      you should use `POST /players/_/login` endpoint
      and add `id` parameter with name entered by user.
      This approach works for all endpoints requiring user's id in url.
    + If user chose Facebook login, you should use Facebook api
      to retrieve facebook auth token.
      Please request `email` permission for that token
      because the server will fetch user's email address from Facebook.
      You then call `POST /federated_login` endpoint
      passing the token retrieved from Facebook API.
        - Federated login endpoint returns either `200 OK` or `201 CREATED` code
          and `created` boolean field.
          If it returns `created=true` then you need to ask the user
          to modify email (because facebook may not return user's email),
          modify nickname (because it is set to Facebook user name
          and the user might want to change it),
          and enter EA gamertag (optionally).
          You can prefill data from object returned by `POST /federated_login` endpoint.
* Now that the user logged in, he needs to choose the game to bet on.
  Game types are listed with `GET /gametypes` endpoint with `full=true` option.
  It will return list of endpoints with parameters: for details consult with endpoint description.
  You should only allow the user to choose `supported` gametypes,
  because he will not be able to `POST /games` for unsupported ones.
    * You will need to show images for that gametypes.
      For that you should use `GET /gametypes/<type>/image` endpoint
      which returns `image/png` binary image.
      By default it has maximum size available, but you can ask the system to shrink it
      by passing either `w`, `h` or both parameters.
      If you pass both of them, image will be shrank down and then cropped to fit.
* After the user chose game type, he will want to bet.
  For that you should use `POST /games` endpoint.
  The user chooses his opponent (either by nickname, gamertag or email),
  the opponent should be already registered on our service.
  Both user and opponent should have "identity" field filled -
  the field whose name is denoted in `identity` value of selected gametype.
  *NEW:* Alternatively the user may want to bet for some other players' game result.
  In such case he will provide `gamertag_creator` and `gamertag_opponent`
  to specify IDs of players for which he want to bet;
  in this situation it is not needed to have identity field filled.
  Also the user chooses `gamemode` (from options provided for selected gametype by `GET /gametypes`).
  And the last, the user should enter bet amount, i.e. how many coins will he bet.
  That amount should not exceed user's balance.
  After posting, the game has `new` status.
* If another user invited you to compete, you will receive PUSH notification about that.
  Also you will see new game in `GET /games` endpoint result.
  You can then accept or decline an invitation by calling `PATCH /games/<id>`
  and passing corresponding value in `state` field.
  Note that you cannot accept an invitation if your balance is insufficient,
  so if that endpoint returns `400` error with `problem=coins` parameter
  you should redirect user to balance deposit screen.
* After your invitation is accepted, you will get corresponding PUSH notification
  and game is immediately considered started.
  This is important point because if you are already playing with that same user
  when he accepted an invitation
  then it is result of ongoing game which will be used to determine
  win or loss here - of course only in case gamemode matches.
* When you win or lose and system notices it, you will get corresponding PUSH notification.
  Also, if you win, you will get an email message.
  `balance` will increase, and `locked` part of balance will decrease.
  So `available` balance will increase 2x the bet amount (your money + your win).
  Also result can be a `draw`.
* To deposit funds (i.e. buy internal coins), you should use `POST /balance/deposit` endpoint.
  It accepts `payment_id` returned by PayPal SDK - see link in endpoint description.
  One coin is equivalent to $1 USD.
  If the user pays in another currency, it will be converted to coins
  according to actual exchange rate (returned by [fixer.io](Fixer.io) service).
  If you want to let the user know how much coins will he get,
  call `POST /balance/deposit` endpoint with `dry_run=true` parameter.
  It will return how many coins would user get,
  but will not check transaction and will not change actual balance.
* For payouts use `POST /balance/withdraw` endpoint.
  Like the previous one, it accepts `dry_run` flag which allows to determine
  how much money will the user get for given amount of coins.
   

### POST /players
Player registration.

*Arguments:*

 * `nickname` - required
 * `email` - required
 * `password`
 * `facebook_token` - optional
 * `ea_gamertag` - optional, should match the one used on EA Games
 * `riot_summonerName` - optional, should match the one used on RIOT (League of Legends)
 * `steam_id` - optional, should be STEAM ID of any kind:
	either integer ID (32- or 64-bit), STEAM_0:1:abcdef, or link to SteamCommunity portal
 * `starcraft_uid` - optional, should be a link to user profile either on battle.net or sc2ranks.com
 * `push_token` - device identifier for push notifications - only for login-related methods.
Can be omitted and provided later with `POST /players/<nick>/pushtoken` endpoint.
 * `bio` - optional player's biography (text)
 * `userpic` - this field can be passed as an uploaded file. It has to be a PNG.

 * `_force`: force registration with invalid gamertag (effectively disables gamertag validation). Should not be used for production.

Returns object with Player resource and auth token. Returns `201` HTTP code.
```json
{
	"player": {Player resource},
	"token": "authentication token"
}
```

### GET /players
Retrieve list of players.
This query is paginated.
By default, it returns all players registered, but output can be filtered.

*Arguments*:

* `filter` - text against which any of player identities should match for that player to be included.
* `filt_op` - operation for filter matching, choices are `startswith` and `contains`, default is `startswith`.
  Matching is always case-insensitive.
* `order` - sorting order, optional. By default players returned are sorted by id, in ascending order.
  Prepend with `-` for descending order.
  Here is a list of supported orders:
    + `lastbet`: order by time of last bet invitation made/received by the player -
      note that it doesn't have to be accepted;
    + `popularity`: order by count of accepted bet invitations (including ones sent by this player);
    + `gamecount`: order by count of games this player has - they include all games: new, accepted, declined and finished
    + `winrate`: order by `winrate` field.
      Note that if you sort by win rate, players will also be sorted by `gamecount` as a secound key.
      This is to ensure list order will be adequate even if some players have no finished games.
  Also player `id` is always used as last key to ensure stable ordering.
  If you choose descending ordering, `id` will also sort descending.
  If you don't specify any ordering, players will be sorted by `id` ascending.
* `results_per_page` defaults to 10, max is 50
* `page` - which page to return, defaults to 1

Result:
```json
{
	"players": [
		// list of Player resources
	],
	"num_results": count of totally available results,
	"total_pages": 10,
	"page": 1
}
```

### GET /players/<id>
Retrieve given player's data.

ID may be either integer internal ID, player's nick or `me`.

For the player requesting will return whole info;
for other players will only return *Limited Player resource*.

### GET /players/<id>/userpic
Returns given player's userpic with `image/png` MIME type.
If given user has no userpic, will return HTTP code `204 NO CONTENT`.

### GET /players/<id>/recent_opponents
Returns list of recent opponents of current player.
Only can be called for self.

### GET /players/<id>/winratehist
Only can be called for self.
Will return win history data for graph building.

Parameters:

* `interval`: either `day`, `week` or `month`
* `range`: count of `interval`s to be returned

In the output intervals will be placed in reverse time order, i.e. latest first.

`wins` value may be a fraction, because game ended as a draw is considered half-win.

```json
{
	"history": [
		{
			"date": "Tue, 18 Aug 2015 23:04:57 GMT", // start of the interval
			"games": 5,
			"wins": 2.5, // float, 0..games
			"rate": 0.5 // float, 0..1
	]
}
```

### GET /players/<id>/leaderposition
Calculates and returns leaderboard position for given player id.
Position is calculated according to `GET /players?order=-winrate` query.

```json
{
	"position": 9
}
```

### PUT /players/<id>/userpic
This is an alternate way to specify userpic.
Accepts `userpic` parameter containing a file to be uploaded.
File has to be in PNG format.
Upon success, returns `{"success": true}`.

Also available as `POST /players/me/userpic`.

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

In url you can include either `nickname`, `ea_gamertag` (or other identity) or email address.

*Arguments*:

 * `password`
 * `push_token` of the current device.
Can be omitted and provided later with `POST /players/<nick>/pushtoken` endpoint.

### POST /players/<nick>/pushtoken
Set push token if it was not provided during login or registration.

*Arguments*:

 * `push_token` - required.

Returns `{"success": true}` on success.
Will return error if you already specified push token on login/registration.
Also will return error if there is no device id in auth token,
which may happen if token was issued before this endpoint was implemented.

### POST /federated_login
Federated login via Facebook or Twitter.

*Arguments*:

 * `svc`: service to use, `facebook` or `twitter`. Defaults to `facebook` for compatibility.
 * `token`: Facebook or Twitter auth token.
	For twitter you should provide both token and secret divided by `:`:
    `...?svc=twitter&token=ACCESS_TOKEN:ACCESS_SECRET` (replace with actual tokens)

For Facebook, token should be requested with `email` permission for server to be able to fetch user's email.

Nickname will be assigned automatically according to Twitter/FB display name,
avoiding any duplicates by adding a number. Later the user may wish to change nickname.

If the user has no userpic provided (wheter it is newly created user or existing one),
this api call will try to fetch userpic from social service.

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


### GET /balance/history
Get transactions history for current player.

This is a paginated query, just like `GET /games`.

Result:
```json
{
	"transactions": [ list of Transaction resources ],
	"page": 1 // current page
	"total_pages": 9,
	"num_results": 83, // total count
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

*Arguments:*

* `betcount`: whether to include count of bets (i.e. popularity)
  and last bet time for each gametype; defaults to `false`
* `latest`: whether to include `latest` list

Will return the following detials about each game type:

* `id` - internal identifier used for that gametype
* `name` - human-readable name of gametype
* `description` - textual description of how to bet and play that specific game.
  Might be `null` if not provided / not required.
  This field may consist of multiple paragraphs divided by `\n` endline character.
* `supported` field - if it is `false` then the only thing you can do with this gametype
is to fetch its image with `GET /gametypes/<type>/image`;
* `gamemodes` lists possible gamemodes for this game type;
* `gamemode_names` lists suggested user-visible names for each gametype;
* `identity` tells which field in player info is used to identify player for this game type.
  When you call `POST /games`, you can provide that IDs as `gamertag_*` values,
  or they will be read from user's profile.
  For example, for FIFA games identity is `ea_gamertag`.
  This means that if you don't provide `gamertag_creator` field,
  system will look for gamertag in your `ea_gamertag` profile field.
  For other game types special fields will be added in future.
* `twitch` - whether twitch link is supported for this gametype:
  `0` means unsupported,
  `1` means optional (i.e. game results can be fetched with other means, but slower),
  and `2` means mandatory (i.e. twitch is the only result polling method for this game).
* `betcount` (if requested) - how many bets were made on this gametype
* `lastbet` (if requested) - when latest bet was made on this gametype, or `null` if no bets were made

Also, for convenience, it returns separate `identities` list
which contains all possible identity fields stored in `Player` resource.
That list may change when we add support for new games,
so it is advised to fetch it from the server rather than hardcode.

And if `latest` parameter is set to `true`,
this endpoint will also return `latest` list ordered by data descendingly
showing last betted gametypes.

```json
{
	"gametypes": [
		{
			"id": "fifa14-xboxone",
			"name": "FIFA-15",
			"supported": true,
			"gamemodes": {
				"fifaSeasons": "FIFA Seasons,
				"fut": "FUT",
				"friendlies": "Friendlies",
				...
			],
			"identity": "ea_gamertag",
			"identity_name": "EA Games GamerTag"
		},
		...,
		{
			"id": "destiny",
			"name": "Destiny",
			"supported": false
		},
		...
	},
	"identities": {
		"ea_gamertag": "EA Gamertag",
		"riot_summonerName": "RIOT Summoner Name",
		...
	},
	"latest": [
		{
			"gametype": "league-of-legends",
			"date": "datetime_object"
		},
		...
	]
}
```

### GET /gametypes/<type>/image
Retrieves a cover image for given game type.

Arguments:

 * `w`: image width (defaults to maximum possible)
 * `h`: image width (defaults to maximum possible)

If only one of arguments is provided, other will be chosen to maintain aspect ratio.
If both are provided, image will be cut to keep aspect ratio.

Returns image itself with corresponding MIME type (most likely PNG).

If image not found for requested gametype, 404 error will be returned.


### GET /gametypes/<type>/background
Retrieves background picture for given game type.
Arguments and behaviour is the same as for `GET /gametypes/<type>/image` endpoint.
Background images are generally different from cover images, have better resolution, 
and exist only for supported games.


### POST /games
Create game invitation.

Arguments:

 * `opponent_id`: either nickname, gamertag or internal numeric id of opponent.
 * `gamertag_creator`: gamertag of the player for which invitation creator roots.
	Optional, defaults to creator's own gamertag (if specified).
 * `gamertag_opponent`: gamertag of the player for which invitation opponent roots.
	Optional, defaults to opponent's own gamertag (if specified).
 * `savetag`: optional. Controls updating creator's default identity for given gametype. Here are options:
    * `never` (default) - don't update
    * `replace` - always replace player's identity with passed one
    * `ignore_if_exists` - if player has no corresponding identity then save,
       else ignore.
    * `fail_if_exists` - if player has no corresponding identity then save,
       else abort query (without creating game object).
       You can then ask user what to do and then resend query with either `never` or `replace`.
 * `gametype`: one of `supported` gametypes from `GET /gametypes` endpoint
 * `gamemode`: one of game modes allowed for chosen gametype according to `GET /gametypes`.
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

Also results can be sorted:

 * `order`: ordering way. Sorts ascending by default; prepend with '-' to sort descending.
   Allowed fields for sorting: `create_date`, `accept_date`, `gametype`, `creator_id`, `opponent_id`.

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

 * `state`: either `accepted` or `declined` for game opponent,
	or `cancelled` for game invitation creator.

Accepting game will immediately lock corresponding amount on player's balance
and the game will be considered started.

If trying to accept and there is no coins enough to cover game's bet amount,
this request will fail with `400` code and additional `problem` field with value `coins`.
In such situation the user should be advised to buy more coins.

Game invitation creator can only make invitation `cancelled`.

Returns *Game resource* object on success.


### GET /games/<id>/msg
Returns binary message file attached to this game, or `204 NO CONTENT` if file was not attached.
Content-type will be passed automatically based on file extension.

### PUT /games/<id>/msg
Attach message to given game, just like `PUT /players/<id>/userpic`.
Message file should be passed as `msg` parameter.
Upon success will return `{"success": true}`.
You cannot upload/change message if game state is not `new`.

For now accepted extensions are `OGG`, `MP3`, `MPG`, `OGV`, `MP4` and `M4A`. I can add more if you need.
Maximum file size is currently 32MB.

This endpoint is also available as `POST /games/<id>/msg` for compatibility.

### GET 

Resources
---------

### Player resource
```json
{
	"id": 23, // internal identifier
	"nickname": "John Smith",
	"email": "user@name.org",
	"facebook_connected": true, // boolean
	"bio": "player's biography, if specified",
	"has_userpic": false,
	"ea_gamertag": "DERP HACKER",
	"riot_summonerName": null,
	"steam_id": null,
	"starcraft_uid": null,
	"tivia_character": null,
	"devices": [ list of Device resources ],
	"balance": 3.95, // current balance in coins
	"balance_info": { Balance resource },
	"gamecount": 3, // how many game invitations are there with this player, including declined and ongoing ones
	"winrate": 0.4, // 0..1 - percentage of games won; can be `null` if there are no finished games!
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

### Transaction resource
```json
{
	"id": 123, // internal identifier, e.g. for tech support usage
	"date": "some datetime", // when this transaction happened
	"type": "withdraw", // one of "deposit", "withdraw", "won", "lost", "other"
	"sum": -100, // amount in coins (either positive or negative, depending on type)
	"balance": 90, // resulting balance in coins *after* this transaction
	"game_id": 135, // for win or lost only - related game id
	"comment": "Converted to 100 USD" // for deposit/withdraw operations
}
```
Comment: `other` transaction type may happen when transaction was made for technical reasons.
One of examples is when user initiates a payout which fails for some reason.
In such situation there will be one transaction of `withdraw` type and another
(with same amount but positive) of `other` type with corresponding description.

### Limited Player resource
Returned if you want to get info about other players.
Doesn't include sensitive information like `balance` or `devices`.
```json
{
	"id": 23, // internal identifier
	"nickname": "John Smith",
	"email": "user@name.org",
	"facebook_connected": true, // boolean
	"bio": "player's biography, if specified",
	"has_userpic": false,
	
	"ea_gamertag": "DERP HACKER",
	"riot_summonerName": null,
	"steam_id": null,
	"starcraft_uid": null,
	"tivia_character": null,
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
 * `cancelled`: creator decided to cancel this invitation,
	and it should not be displayed in interface.
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
	"has_message": true, // bool, tells if GET /games/<id>/msg will work
	"create_date": "RFC datetime",
	"state": "finished", // see above
	"accept_date": "RFC datetime", // date of eiter accepting or declining game, null for new games
	"winner": "opponent", // either "creator", "opponent" or "draw"
	"details": "Manchester vs Barcelona, score 1-3", // game result details, it depends on game and poller
	"finish_date": "RFC datetime" // date when this game was finished, according to EA servers
}
```
