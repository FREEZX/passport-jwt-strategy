This is a jwt strategy implementation, that can be used as a replacement to `passport.session()`.

## Usage

First import the strategy:

```
	passport.use(new JwtSession(<Insert secret here>));
```

After `passport.initialize()`, place `app.use(passport.authenticate('jwt', options));`

The `options` field can currently take one field: `token`, that can take either `header` or `query` string values (default is `header`), which tells it where to search for the token.
The `header` option looks for it in the `Authorization` request header, and query gets the token from the `token` query parameter.

It will automatically call deserializeUser if a jwt token is present.
For everything to work properly you need to be sending a token that contains `user` in the payload, this is the user id we are deserializing.

For sample implementation code, check out [Nuke.js](https://github.com/FREEZX/nuke.js).