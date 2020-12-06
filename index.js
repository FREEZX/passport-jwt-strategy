'use strict';

/**
 * Module dependencies.
 */
const pause = require('pause'),
	Strategy = require('passport-strategy'),
	{ promisify } = require('util'),
	jwt = require('jsonwebtoken'),
	JWTVerify = promisify(jwt.verify).bind(jwt);

const headerName = requestArg => {
	return requestArg.split('').reduce((memo, ch) => {
		return memo + (ch.toUpperCase() === ch ? '-' + ch.toLowerCase() : ch);
	}, 'x' + (requestArg.charAt(0) === requestArg.charAt(0).toUpperCase() ? '' : '-'));
};

/**
 * `JwtStrategy` class.
 *
 */

class JwtStrategy extends Strategy {
	/**
	 * `JwtStrategy` constructor.
	 *
	 * @api public
	 */
	constructor(options) {
		super();
		options = options || {};
		this.name = 'jwt';

		this.options = {
			secret: options.secret,
			maxAge: options.maxAge || 86400,
			algorithms: options.algorithms || 'HS256',
			requestKey: options.requestKey || 'user',
			requestArg: options.requestArg || 'accessToken',
		};
	}

	/**
	 * Authenticate request based on the current session state.
	 *
	 * The session authentication strategy uses the session to restore any login
	 * state across requests.  If a login session has been established, `req.user`
	 * will be populated with the current user.
	 *
	 * This strategy is registered automatically by Passport.
	 *
	 * @param {Object} req
	 * @param {Object} options
	 * @api protected
	 */
	async authenticate(req, options) {
		if (!req._passport) {
			return this.error(new Error('passport.initialize() middleware not in use'));
		}

		options = this.options || {};

		const requestHeader = headerName(options.requestArg);

		let payload = {};

		let token = req.query ? req.query[options.requestArg] : false;
		token = token || req.headers[requestHeader];
		token = token || (req.signedCookies ? req.signedCookies[options.requestArg] : false);
		token = token || (req.cookies ? req.cookies[options.requestArg] : false);

		if (token) {
			try {
				payload = await JWTVerify(token, options.secret, options);
				// eslint-disable-next-line no-empty
			} catch (e) {}
		}

		const su = payload.user;
		if ((su || su === 0) && (payload.exp > Date.now() || !payload.exp)) {
			const paused = options.pauseStream ? pause(req) : null;
			req._passport.instance.deserializeUser(su, req, (err, user) => {
				if (err) {
					return this.error(err);
				}
				if (!user) {
					if (req._passport && req._passport.session) {
						delete req._passport.session.user;
					}
					this.pass();
					if (paused) {
						paused.resume();
					}
					return;
				}
				const property = req._passport.instance._userProperty || 'user';
				req[property] = user;
				this.pass();
				if (paused) {
					paused.resume();
				}
			});
		} else {
			this.pass();
		}
	}
}

/**
 * Expose `JwtStrategy`.
 */
module.exports = JwtStrategy;
