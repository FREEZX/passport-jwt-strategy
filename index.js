'use strict';

/**
 * Module dependencies.
 */
 const 	pause = require('pause'),
 	Strategy = require('passport-strategy'),
 	jwt = require('jwt-simple');

 function headerName(requestArg){
 	return requestArg.split('').reduce(function(memo, ch){
 		return memo + (ch.toUpperCase() === ch ? '-' + ch.toLowerCase() : ch);
 	}, 'x' + (requestArg.charAt(0) === requestArg.charAt(0).toUpperCase() ? '' : '-'));
 }

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
 	constructor(options){
 		super();
 		options = options || {};
 		this.name = 'jwt';

 		this.options = {
 			secret: options.secret,
 			maxAge: options.maxAge || 86400,
 			requestKey: options.requestKey || 'user',
 			requestArg: options.requestArg || 'accessToken'
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
 	authenticate(req, options){
 		if (!req._passport) { return this.error(new Error('passport.initialize() middleware not in use')); }
 		options = this.options || {};

 		const requestHeader = headerName(options.requestArg);

 		let payload = {};

 		let token = req.query ? req.query[options.requestArg] : false;
 		token = token || req.headers[requestHeader];
 		token = token || (req.cookies ? req.cookies[requestHeader] : false);

 		if(token){
 			try {
 				payload = jwt.decode(token, options.secret);
 			} catch(e) {

 			}
 		}

 		const su = payload.user;
 		if ((su || su === 0) && (payload.expires > Date.now() || !payload.expires) ) {

 			const paused = options.pauseStream ? pause(req) : null;
 			req._passport.instance.deserializeUser(su, req, function(err, user) {
 				if (err) { return super.error(err); }
 				if (!user) {
 					delete req._passport.session.user;
 					self.pass();
 					if (paused) {
 						paused.resume();
 					}
 					return;
 				}
 				const property = req._passport.instance._userProperty || 'user';
 				req[property] = user;
 				super.pass();
 				if (paused) {
 					paused.resume();
 				}
 			});
 		} else {
 			super.pass();
 		}
 	}
 }


/**
 * Expose `JwtStrategy`.
 */
 module.exports = JwtStrategy;
