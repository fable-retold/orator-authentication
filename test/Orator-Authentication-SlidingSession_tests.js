/**
* Unit tests for the opt-in sliding-session behavior of Orator Authentication.
*
* Fixed (default): a session lives sessionTTL from CreatedAt with no renewal.
* Sliding (opt-in): the TTL window is measured from the last authenticated
* access, so ongoing activity keeps the session alive and only genuine
* inactivity longer than sessionTTL expires it.
*
* @license     MIT
*
* @author      Steven Velozo <steven@velozo.com>
*/

const Chai = require("chai");
const Expect = Chai.expect;

const libFable = require('fable');
const libOrator = require('orator');
const libOratorAuthentication = require('../source/Orator-Authentication.js');

const defaultFableSettings = (
	{
		Product: 'OratorAuthentication-Sliding-Tests',
		ProductVersion: '0.0.0',
		APIServerPort: 0
	});

// Build an OratorAuthentication instance with the given options (no server start
// needed -- these tests drive the synchronous session store + _cookieSession).
function makeAuth(pFableSettings, pAuthOptions)
{
	let tmpFableSettings = Object.assign({}, defaultFableSettings, pFableSettings || {});
	let tmpFable = new libFable(tmpFableSettings);
	tmpFable.serviceManager.addServiceType('Orator', libOrator);
	tmpFable.serviceManager.addServiceType('OratorAuthentication', libOratorAuthentication);
	tmpFable.serviceManager.instantiateServiceProvider('Orator', {});
	return tmpFable.serviceManager.instantiateServiceProvider('OratorAuthentication', pAuthOptions || {});
}

// A request whose Cookie header names the given session under the auth's cookie.
function requestForSession(pAuth, pSessionID)
{
	return { headers: { cookie: pAuth.cookieName + '=' + pSessionID } };
}

suite
	(
		'Orator Authentication Sliding Session',
		function ()
		{
			suite
				(
					'Configuration',
					function ()
					{
						test
							(
								'defaults to false (fixed TTL)',
								() =>
								{
									let tmpAuth = makeAuth({}, {});
									Expect(tmpAuth.slidingSession).to.equal(false);
								}
							);

						test
							(
								'enables via options',
								() =>
								{
									let tmpAuth = makeAuth({}, { SlidingSession: true });
									Expect(tmpAuth.slidingSession).to.equal(true);
								}
							);

						test
							(
								'enables via fable settings fallback',
								() =>
								{
									let tmpAuth = makeAuth({ OratorAuthenticationSlidingSession: true }, {});
									Expect(tmpAuth.slidingSession).to.equal(true);
								}
							);

						test
							(
								'options take precedence over settings',
								() =>
								{
									let tmpAuth = makeAuth({ OratorAuthenticationSlidingSession: true }, { SlidingSession: false });
									Expect(tmpAuth.slidingSession).to.equal(false);
								}
							);
					}
				);

			suite
				(
					'Expiry behavior',
					function ()
					{
						test
							(
								'fixed (default): expires at TTL from CreatedAt even with recent access',
								() =>
								{
									let tmpAuth = makeAuth({}, { SessionTTL: 1000 });
									let tmpSession = tmpAuth._createSession({ IDUser: 1, UserName: 'a' });
									// Created 2s ago (past the 1s TTL), but accessed just now.
									tmpSession.CreatedAt = Date.now() - 2000;
									tmpSession.LastAccess = Date.now();
									let tmpResolved = tmpAuth._cookieSession(requestForSession(tmpAuth, tmpSession.SessionID));
									// Fixed window is anchored to CreatedAt -> expired.
									Expect(tmpResolved).to.equal(null);
								}
							);

						test
							(
								'sliding: survives past the base TTL while activity continues',
								() =>
								{
									let tmpAuth = makeAuth({}, { SessionTTL: 1000, SlidingSession: true });
									let tmpSession = tmpAuth._createSession({ IDUser: 1, UserName: 'a' });
									// Created long ago (well past the 1s TTL) but accessed recently.
									tmpSession.CreatedAt = Date.now() - 60000;
									tmpSession.LastAccess = Date.now() - 200;
									let tmpResolved = tmpAuth._cookieSession(requestForSession(tmpAuth, tmpSession.SessionID));
									// Sliding window is anchored to LastAccess -> still valid...
									Expect(tmpResolved).to.not.equal(null);
									// ...and the access advanced the window.
									Expect(tmpResolved.LastAccess).to.be.closeTo(Date.now(), 500);
								}
							);

						test
							(
								'sliding: expires after genuine inactivity longer than the TTL',
								() =>
								{
									let tmpAuth = makeAuth({}, { SessionTTL: 1000, SlidingSession: true });
									let tmpSession = tmpAuth._createSession({ IDUser: 1, UserName: 'a' });
									// Last activity was 2s ago -> past the 1s inactivity window.
									tmpSession.CreatedAt = Date.now() - 5000;
									tmpSession.LastAccess = Date.now() - 2000;
									let tmpResolved = tmpAuth._cookieSession(requestForSession(tmpAuth, tmpSession.SessionID));
									Expect(tmpResolved).to.equal(null);
								}
							);

						test
							(
								'sliding: a steady stream of accesses keeps a session alive indefinitely',
								() =>
								{
									let tmpAuth = makeAuth({}, { SessionTTL: 1000, SlidingSession: true });
									let tmpSession = tmpAuth._createSession({ IDUser: 1, UserName: 'a' });
									tmpSession.CreatedAt = Date.now() - 10000; // old session
									// Simulate repeated accesses, each within the window. Every call
									// resolves non-null and refreshes LastAccess to "now".
									for (let i = 0; i < 4; i++)
									{
										let tmpResolved = tmpAuth._cookieSession(requestForSession(tmpAuth, tmpSession.SessionID));
										Expect(tmpResolved).to.not.equal(null);
										Expect(tmpResolved.LastAccess).to.be.closeTo(Date.now(), 500);
									}
								}
							);
					}
				);
		}
	);
