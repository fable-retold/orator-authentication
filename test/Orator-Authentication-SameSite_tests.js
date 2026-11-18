/**
* Unit tests for the SameSite attribute on the Orator Authentication session cookie.
*
* Default is SameSite=Lax, so a cross-site form POST does not carry the session
* in any browser. CookieSameSite (or the OratorAuthenticationCookieSameSite fable
* setting) picks Strict / Lax / None, or false to omit the attribute (the legacy
* header). The set cookie and the clearing cookie share one attribute builder.
*
* The route-level tests run a real Restify server on an ephemeral port, because
* the IPC service server has no response headers to inspect.
*
* @license     MIT
*
* @author      Steven Velozo <steven@velozo.com>
*/

const Chai = require("chai");
const Expect = Chai.expect;

const libHTTP = require('http');

const libFable = require('fable');
const libOrator = require('orator');
const libOratorServiceServerRestify = require('orator-serviceserver-restify');
const libOratorAuthentication = require('../source/Orator-Authentication.js');

const defaultFableSettings = (
	{
		Product: 'OratorAuthentication-SameSite-Tests',
		ProductVersion: '0.0.0',
		APIServerPort: 0
	});

const EPOCH_EXPIRES = 'Expires=Thu, 01 Jan 1970 00:00:00 GMT';

/**
 * Build an OratorAuthentication instance (no server start). Warnings logged by
 * the service while it is constructed are pushed onto pWarnings when given.
 *
 * @param {object} pFableSettings - Fable settings to merge with defaults.
 * @param {object} pAuthOptions - Options for the OratorAuthentication instance.
 * @param {Array} pWarnings - (optional) Collects the text of every log.warn call.
 */
function makeAuth(pFableSettings, pAuthOptions, pWarnings)
{
	let tmpFableSettings = Object.assign({}, defaultFableSettings, pFableSettings || {});
	let tmpFable = new libFable(tmpFableSettings);

	if (Array.isArray(pWarnings))
	{
		let tmpOriginalWarn = tmpFable.Logging.warn.bind(tmpFable.Logging);
		tmpFable.Logging.warn = (pMessage, pDatum) =>
		{
			pWarnings.push(String(pMessage));
			return tmpOriginalWarn(pMessage, pDatum);
		};
	}

	tmpFable.serviceManager.addServiceType('Orator', libOrator);
	tmpFable.serviceManager.addServiceType('OratorAuthentication', libOratorAuthentication);
	tmpFable.serviceManager.instantiateServiceProvider('Orator', {});
	return tmpFable.serviceManager.instantiateServiceProvider('OratorAuthentication', pAuthOptions || {});
}

/**
 * Capture the Set-Cookie header a cookie helper writes. pVia picks which
 * response method the mock exposes ('setHeader' or 'header').
 */
function captureCookie(pAuth, pVia, fWrite)
{
	let tmpCaptured = null;
	let tmpMockResponse = {};
	tmpMockResponse[pVia] = (pName, pValue) =>
	{
		tmpCaptured = { Name: pName, Value: pValue };
	};
	fWrite(tmpMockResponse);
	return tmpCaptured;
}

function setCookieHeader(pAuth, pSessionID)
{
	return captureCookie(pAuth, 'setHeader', (pResponse) => pAuth._setSessionCookie(pResponse, pSessionID)).Value;
}

function clearCookieHeader(pAuth)
{
	return captureCookie(pAuth, 'setHeader', (pResponse) => pAuth._clearSessionCookie(pResponse)).Value;
}

/**
 * Start a Fable + Orator (Restify) + OratorAuthentication harness on an
 * ephemeral port. A tiny query-string middleware stands in for restify's
 * queryParser plugin so the OAuth callback can read ?state=.
 */
function createRestifyHarness(pFableSettings, pAuthOptions, fCallback)
{
	let tmpFableSettings = Object.assign({}, defaultFableSettings, pFableSettings || {});
	let tmpFable = new libFable(tmpFableSettings);

	tmpFable.serviceManager.addServiceType('OratorServiceServer', libOratorServiceServerRestify);
	tmpFable.serviceManager.instantiateServiceProvider('OratorServiceServer', {});
	tmpFable.serviceManager.addServiceType('Orator', libOrator);
	tmpFable.serviceManager.addServiceType('OratorAuthentication', libOratorAuthentication);

	let tmpOrator = tmpFable.serviceManager.instantiateServiceProvider('Orator', {});
	let tmpAuth = tmpFable.serviceManager.instantiateServiceProvider('OratorAuthentication', pAuthOptions || {});

	tmpOrator.startService(
		() =>
		{
			tmpOrator.serviceServer.use(
				(pRequest, pResponse, fNext) =>
				{
					pRequest.query = Object.fromEntries(new URL(pRequest.url, 'http://localhost').searchParams);
					return fNext();
				});

			return fCallback(
				{
					fable: tmpFable,
					orator: tmpOrator,
					auth: tmpAuth,
					port: tmpOrator.serviceServer.server.address().port
				});
		});
}

/**
 * Make a real HTTP request against the harness.
 *
 * @param {object} pHarness - From createRestifyHarness
 * @param {string} pMethod - GET / POST
 * @param {string} pPath - Request path
 * @param {object} pOptions - { Body: object, Cookie: string }
 * @param {Function} fCallback - (pError, { Status, Headers, SetCookie: [], Text, JSON })
 */
function httpRequest(pHarness, pMethod, pPath, pOptions, fCallback)
{
	let tmpOptions = pOptions || {};
	let tmpPayload = (`Body` in tmpOptions) ? JSON.stringify(tmpOptions.Body) : null;
	let tmpHeaders = {};
	if (tmpPayload !== null)
	{
		tmpHeaders['Content-Type'] = 'application/json';
		tmpHeaders['Content-Length'] = Buffer.byteLength(tmpPayload);
	}
	if (tmpOptions.Cookie)
	{
		tmpHeaders['Cookie'] = tmpOptions.Cookie;
	}

	let tmpRequest = libHTTP.request(
		{
			host: '127.0.0.1',
			port: pHarness.port,
			method: pMethod,
			path: pPath,
			headers: tmpHeaders
		},
		(pResponse) =>
		{
			let tmpChunks = [];
			pResponse.on('data', (pChunk) => tmpChunks.push(pChunk));
			pResponse.on('end',
				() =>
				{
					let tmpText = Buffer.concat(tmpChunks).toString('utf8');
					let tmpJSON = null;
					try { tmpJSON = tmpText.length ? JSON.parse(tmpText) : null; }
					catch (pParseError) { tmpJSON = null; }
					return fCallback(null,
						{
							Status: pResponse.statusCode,
							Headers: pResponse.headers,
							SetCookie: [].concat(pResponse.headers['set-cookie'] || []),
							Text: tmpText,
							JSON: tmpJSON
						});
				});
		});
	tmpRequest.on('error', (pError) => fCallback(pError));
	if (tmpPayload !== null)
	{
		tmpRequest.write(tmpPayload);
	}
	tmpRequest.end();
}

/**
 * Run assertions, always stop the server, then report to mocha. Keeps a failed
 * assertion from leaving a listening socket behind.
 */
function finish(pHarness, fDone, fAssertions)
{
	let tmpAssertionError = null;
	try
	{
		fAssertions();
	}
	catch (pError)
	{
		tmpAssertionError = pError;
	}
	pHarness.orator.stopService(
		() =>
		{
			return fDone(tmpAssertionError);
		});
}

/**
 * A mock OAuth provider whose callback always succeeds (no network).
 */
function createMockOAuthProvider()
{
	return (
		{
			initialize: () => Promise.resolve(),
			buildAuthorizationURL: (pState) => Promise.resolve(`https://mock-provider.example.com/authorize?state=${pState}`),
			handleCallback: () => Promise.resolve(
				{
					Claims: { sub: 'mock-user-123', preferred_username: 'mockuser', email: 'mock@example.com' },
					Tokens: { AccessToken: 'mock-access-token', RefreshToken: null, ExpiresAt: Date.now() + 3600000 }
				})
		});
}

suite
(
	'Orator Authentication SameSite Cookie',
	() =>
	{
		suite
		(
			'Configuration',
			() =>
			{
				test
				(
					'defaults to Lax',
					() =>
					{
						let tmpWarnings = [];
						let tmpAuth = makeAuth({}, {}, tmpWarnings);
						Expect(tmpAuth.cookieSameSite).to.equal('Lax');
						Expect(tmpWarnings).to.deep.equal([]);
					}
				);

				test
				(
					'accepts Strict via options',
					() =>
					{
						let tmpAuth = makeAuth({}, { CookieSameSite: 'Strict' });
						Expect(tmpAuth.cookieSameSite).to.equal('Strict');
					}
				);

				test
				(
					'accepts None via options when CookieSecure is true',
					() =>
					{
						let tmpWarnings = [];
						let tmpAuth = makeAuth({}, { CookieSameSite: 'None', CookieSecure: true }, tmpWarnings);
						Expect(tmpAuth.cookieSameSite).to.equal('None');
						Expect(tmpWarnings).to.deep.equal([]);
					}
				);

				test
				(
					'is case-insensitive and trims whitespace',
					() =>
					{
						Expect(makeAuth({}, { CookieSameSite: 'lax' }).cookieSameSite).to.equal('Lax');
						Expect(makeAuth({}, { CookieSameSite: ' STRICT ' }).cookieSameSite).to.equal('Strict');
						Expect(makeAuth({}, { CookieSameSite: 'nOnE', CookieSecure: true }).cookieSameSite).to.equal('None');
					}
				);

				test
				(
					'false omits the attribute, with no warning',
					() =>
					{
						let tmpWarnings = [];
						let tmpAuth = makeAuth({}, { CookieSameSite: false }, tmpWarnings);
						Expect(tmpAuth.cookieSameSite).to.equal(false);
						Expect(tmpWarnings).to.deep.equal([]);
					}
				);

				test
				(
					'uses the fable settings fallback',
					() =>
					{
						let tmpAuth = makeAuth({ OratorAuthenticationCookieSameSite: 'Strict' }, {});
						Expect(tmpAuth.cookieSameSite).to.equal('Strict');

						let tmpLegacyAuth = makeAuth({ OratorAuthenticationCookieSameSite: false }, {});
						Expect(tmpLegacyAuth.cookieSameSite).to.equal(false);
					}
				);

				test
				(
					'options take precedence over fable settings',
					() =>
					{
						let tmpAuth = makeAuth({ OratorAuthenticationCookieSameSite: 'Strict' }, { CookieSameSite: 'Lax' });
						Expect(tmpAuth.cookieSameSite).to.equal('Lax');

						let tmpOffAuth = makeAuth({ OratorAuthenticationCookieSameSite: 'Strict' }, { CookieSameSite: false });
						Expect(tmpOffAuth.cookieSameSite).to.equal(false);
					}
				);

				test
				(
					'null and undefined fall back to Lax, with no warning',
					() =>
					{
						let tmpWarnings = [];
						Expect(makeAuth({}, { CookieSameSite: null }, tmpWarnings).cookieSameSite).to.equal('Lax');
						Expect(makeAuth({}, { CookieSameSite: undefined }, tmpWarnings).cookieSameSite).to.equal('Lax');
						Expect(makeAuth({ OratorAuthenticationCookieSameSite: null }, {}, tmpWarnings).cookieSameSite).to.equal('Lax');
						Expect(makeAuth({ OratorAuthenticationCookieSameSite: undefined }, {}, tmpWarnings).cookieSameSite).to.equal('Lax');
						Expect(tmpWarnings).to.deep.equal([]);
					}
				);

				test
				(
					'None without CookieSecure falls back to Lax and warns',
					() =>
					{
						let tmpWarnings = [];
						let tmpAuth = makeAuth({}, { CookieSameSite: 'None' }, tmpWarnings);
						Expect(tmpAuth.cookieSameSite).to.equal('Lax');
						Expect(tmpWarnings.length).to.equal(1);
						Expect(tmpWarnings[0]).to.include('OratorAuthentication');
						Expect(tmpWarnings[0]).to.include('CookieSecure');
						Expect(tmpWarnings[0]).to.include('using Lax');

						// Same rule when None arrives through the settings fallback.
						let tmpSettingsWarnings = [];
						let tmpSettingsAuth = makeAuth({ OratorAuthenticationCookieSameSite: 'none' }, {}, tmpSettingsWarnings);
						Expect(tmpSettingsAuth.cookieSameSite).to.equal('Lax');
						Expect(tmpSettingsWarnings.length).to.equal(1);
					}
				);

				test
				(
					'garbage values fall back to Lax and warn, naming the bad value',
					() =>
					{
						let tmpCases =
						[
							{ Value: 'Sideways', Shown: '"Sideways"' },
							{ Value: '', Shown: '""' },
							{ Value: true, Shown: 'true' },
							{ Value: 0, Shown: '0' },
							{ Value: 42, Shown: '42' },
							{ Value: { Mode: 'Lax' }, Shown: '[object Object]' }
						];

						for (let i = 0; i < tmpCases.length; i++)
						{
							let tmpWarnings = [];
							let tmpAuth = makeAuth({}, { CookieSameSite: tmpCases[i].Value }, tmpWarnings);
							Expect(tmpAuth.cookieSameSite, `value ${tmpCases[i].Shown}`).to.equal('Lax');
							Expect(tmpWarnings.length, `value ${tmpCases[i].Shown}`).to.equal(1);
							Expect(tmpWarnings[0]).to.include(tmpCases[i].Shown);
							Expect(tmpWarnings[0]).to.include('using Lax');
						}
					}
				);

				test
				(
					'_normalizeCookieSameSite is a pure { Value, Warning } mapping',
					() =>
					{
						let tmpAuth = makeAuth({}, {});

						Expect(tmpAuth._normalizeCookieSameSite('Strict', false)).to.deep.equal({ Value: 'Strict', Warning: null });
						Expect(tmpAuth._normalizeCookieSameSite('lax', false)).to.deep.equal({ Value: 'Lax', Warning: null });
						Expect(tmpAuth._normalizeCookieSameSite('None', true)).to.deep.equal({ Value: 'None', Warning: null });
						Expect(tmpAuth._normalizeCookieSameSite(false, false)).to.deep.equal({ Value: false, Warning: null });
						Expect(tmpAuth._normalizeCookieSameSite(undefined, false)).to.deep.equal({ Value: 'Lax', Warning: null });
						Expect(tmpAuth._normalizeCookieSameSite(null, true)).to.deep.equal({ Value: 'Lax', Warning: null });

						let tmpNoneInsecure = tmpAuth._normalizeCookieSameSite('None', false);
						Expect(tmpNoneInsecure.Value).to.equal('Lax');
						Expect(tmpNoneInsecure.Warning).to.be.a('string');

						let tmpGarbage = tmpAuth._normalizeCookieSameSite('bogus', true);
						Expect(tmpGarbage.Value).to.equal('Lax');
						Expect(tmpGarbage.Warning).to.include('"bogus"');

						// An object with no toString must not throw.
						let tmpBare = tmpAuth._normalizeCookieSameSite(Object.create(null), false);
						Expect(tmpBare.Value).to.equal('Lax');
						Expect(tmpBare.Warning).to.include('[object]');
					}
				);
			}
		);

		suite
		(
			'Cookie Header',
			() =>
			{
				test
				(
					'default set and clear headers end with SameSite=Lax',
					() =>
					{
						let tmpAuth = makeAuth({}, {});
						Expect(setCookieHeader(tmpAuth, 'abc')).to.equal('SessionID=abc; Path=/; HttpOnly; SameSite=Lax');
						Expect(clearCookieHeader(tmpAuth)).to.equal(`SessionID=; Path=/; ${EPOCH_EXPIRES}; HttpOnly; SameSite=Lax`);
					}
				);

				test
				(
					'Strict is emitted on both set and clear',
					() =>
					{
						let tmpAuth = makeAuth({}, { CookieName: 'RetoldSessionID', CookieSameSite: 'Strict' });
						Expect(setCookieHeader(tmpAuth, 'abc')).to.equal('RetoldSessionID=abc; Path=/; HttpOnly; SameSite=Strict');
						Expect(clearCookieHeader(tmpAuth)).to.equal(`RetoldSessionID=; Path=/; ${EPOCH_EXPIRES}; HttpOnly; SameSite=Strict`);
					}
				);

				test
				(
					'None with CookieSecure puts SameSite after Secure',
					() =>
					{
						let tmpAuth = makeAuth({}, { CookieSameSite: 'None', CookieSecure: true });
						let tmpSet = setCookieHeader(tmpAuth, 'abc');
						Expect(tmpSet).to.equal('SessionID=abc; Path=/; HttpOnly; Secure; SameSite=None');
						Expect(tmpSet).to.include('; Secure; SameSite=None');
						Expect(clearCookieHeader(tmpAuth)).to.equal(`SessionID=; Path=/; ${EPOCH_EXPIRES}; HttpOnly; Secure; SameSite=None`);
					}
				);

				test
				(
					'false produces the legacy header byte for byte',
					() =>
					{
						let tmpAuth = makeAuth({}, { CookieSameSite: false });
						let tmpSet = setCookieHeader(tmpAuth, 'abc');
						let tmpClear = clearCookieHeader(tmpAuth);
						Expect(tmpSet).to.equal('SessionID=abc; Path=/; HttpOnly');
						Expect(tmpClear).to.equal(`SessionID=; Path=/; ${EPOCH_EXPIRES}; HttpOnly`);
						Expect(tmpSet).to.not.include('SameSite');
						Expect(tmpClear).to.not.include('SameSite');

						let tmpSecureAuth = makeAuth({}, { CookieSameSite: false, CookieSecure: true });
						Expect(setCookieHeader(tmpSecureAuth, 'abc')).to.equal('SessionID=abc; Path=/; HttpOnly; Secure');
						Expect(clearCookieHeader(tmpSecureAuth)).to.equal(`SessionID=; Path=/; ${EPOCH_EXPIRES}; HttpOnly; Secure`);
					}
				);

				test
				(
					'attribute order holds with HttpOnly off and a custom path',
					() =>
					{
						let tmpAuth = makeAuth({}, { CookieHttpOnly: false, CookiePath: '/app', CookieSameSite: 'strict' });
						Expect(setCookieHeader(tmpAuth, 'abc')).to.equal('SessionID=abc; Path=/app; SameSite=Strict');
						Expect(clearCookieHeader(tmpAuth)).to.equal(`SessionID=; Path=/app; ${EPOCH_EXPIRES}; SameSite=Strict`);
					}
				);

				test
				(
					'the header() response branch gets the same SameSite value',
					() =>
					{
						let tmpAuth = makeAuth({}, {});
						let tmpSet = captureCookie(tmpAuth, 'header', (pResponse) => tmpAuth._setSessionCookie(pResponse, 'abc'));
						let tmpClear = captureCookie(tmpAuth, 'header', (pResponse) => tmpAuth._clearSessionCookie(pResponse));
						Expect(tmpSet.Name).to.equal('Set-Cookie');
						Expect(tmpSet.Value).to.equal('SessionID=abc; Path=/; HttpOnly; SameSite=Lax');
						Expect(tmpClear.Name).to.equal('Set-Cookie');
						Expect(tmpClear.Value).to.equal(`SessionID=; Path=/; ${EPOCH_EXPIRES}; HttpOnly; SameSite=Lax`);
					}
				);
			}
		);

		suite
		(
			'Real HTTP Responses',
			() =>
			{
				test
				(
					'POST /1.0/Authenticate sets the session cookie with SameSite=Lax by default',
					(fDone) =>
					{
						createRestifyHarness(null, { CookieName: 'RetoldSessionID' },
							(pHarness) =>
							{
								pHarness.auth.connectRoutes();

								httpRequest(pHarness, 'POST', '/1.0/Authenticate', { Body: { UserName: 'operator', Password: 'pass' } },
									(pError, pResult) =>
									{
										finish(pHarness, fDone,
											() =>
											{
												Expect(pError).to.equal(null);
												Expect(pResult.Status).to.equal(200);
												Expect(pResult.JSON.LoggedIn).to.equal(true);
												Expect(pResult.SetCookie.length).to.equal(1);
												Expect(pResult.SetCookie[0]).to.equal(`RetoldSessionID=${pResult.JSON.SessionID}; Path=/; HttpOnly; SameSite=Lax`);
											});
									});
							});
					}
				);

				test
				(
					'GET /1.0/Authenticate/:username/:password sets SameSite=Lax by default',
					(fDone) =>
					{
						createRestifyHarness(null, null,
							(pHarness) =>
							{
								pHarness.auth.connectRoutes();

								httpRequest(pHarness, 'GET', '/1.0/Authenticate/operator/pass', null,
									(pError, pResult) =>
									{
										finish(pHarness, fDone,
											() =>
											{
												Expect(pError).to.equal(null);
												Expect(pResult.Status).to.equal(200);
												Expect(pResult.JSON.LoggedIn).to.equal(true);
												Expect(pResult.SetCookie[0]).to.equal(`SessionID=${pResult.JSON.SessionID}; Path=/; HttpOnly; SameSite=Lax`);
											});
									});
							});
					}
				);

				test
				(
					'GET /1.0/Deauthenticate clears the cookie with the same SameSite (default Lax)',
					(fDone) =>
					{
						createRestifyHarness(null, null,
							(pHarness) =>
							{
								pHarness.auth.connectRoutes();

								httpRequest(pHarness, 'POST', '/1.0/Authenticate', { Body: { UserName: 'operator', Password: 'pass' } },
									(pLoginError, pLogin) =>
									{
										if (pLoginError)
										{
											return finish(pHarness, fDone, () => { throw pLoginError; });
										}
										let tmpSessionID = pLogin.JSON.SessionID;

										httpRequest(pHarness, 'GET', '/1.0/Deauthenticate', { Cookie: `SessionID=${tmpSessionID}` },
											(pError, pResult) =>
											{
												finish(pHarness, fDone,
													() =>
													{
														Expect(pError).to.equal(null);
														Expect(pResult.JSON.LoggedIn).to.equal(false);
														Expect(pResult.SetCookie[0]).to.equal(`SessionID=; Path=/; ${EPOCH_EXPIRES}; HttpOnly; SameSite=Lax`);
														Expect(pHarness.auth.sessionStore.has(tmpSessionID)).to.equal(false);
													});
											});
									});
							});
					}
				);

				test
				(
					'POST /1.0/Deauthenticate clears with the same configured SameSite as login (Strict)',
					(fDone) =>
					{
						createRestifyHarness(null, { CookieSameSite: 'Strict' },
							(pHarness) =>
							{
								pHarness.auth.connectRoutes();

								httpRequest(pHarness, 'POST', '/1.0/Authenticate', { Body: { UserName: 'operator', Password: 'pass' } },
									(pLoginError, pLogin) =>
									{
										if (pLoginError)
										{
											return finish(pHarness, fDone, () => { throw pLoginError; });
										}
										let tmpSessionID = pLogin.JSON.SessionID;

										httpRequest(pHarness, 'POST', '/1.0/Deauthenticate', { Cookie: `SessionID=${tmpSessionID}` },
											(pError, pResult) =>
											{
												finish(pHarness, fDone,
													() =>
													{
														Expect(pError).to.equal(null);
														Expect(pLogin.SetCookie[0]).to.match(/; SameSite=Strict$/);
														Expect(pResult.SetCookie[0]).to.equal(`SessionID=; Path=/; ${EPOCH_EXPIRES}; HttpOnly; SameSite=Strict`);
													});
											});
									});
							});
					}
				);

				test
				(
					'CookieSameSite false sends the legacy header with no SameSite',
					(fDone) =>
					{
						createRestifyHarness(null, { CookieSameSite: false },
							(pHarness) =>
							{
								pHarness.auth.connectRoutes();

								httpRequest(pHarness, 'POST', '/1.0/Authenticate', { Body: { UserName: 'operator', Password: 'pass' } },
									(pError, pResult) =>
									{
										finish(pHarness, fDone,
											() =>
											{
												Expect(pError).to.equal(null);
												Expect(pResult.SetCookie[0]).to.equal(`SessionID=${pResult.JSON.SessionID}; Path=/; HttpOnly`);
											});
									});
							});
					}
				);

				test
				(
					'the OAuth callback session cookie carries SameSite=Lax',
					(fDone) =>
					{
						createRestifyHarness(null,
							{
								OAuthProviders:
								{
									'mock':
									{
										Type: 'openid-connect',
										IssuerURL: 'https://mock.example.com',
										ClientID: 'test',
										ClientSecret: 'test',
										CallbackURL: 'http://localhost:9999/1.0/OAuth/Callback/mock'
									}
								}
							},
							(pHarness) =>
							{
								pHarness.auth.oauthProviderInstances['mock'] = createMockOAuthProvider();
								pHarness.auth.connectRoutes();

								let tmpState = 'samesite-oauth-state';
								pHarness.auth._storeOAuthState(tmpState,
									{
										CodeVerifier: 'test-code-verifier',
										Nonce: 'test-nonce',
										Provider: 'mock'
									});

								httpRequest(pHarness, 'GET', `/1.0/OAuth/Callback/mock?code=mock-code&state=${tmpState}`, null,
									(pError, pResult) =>
									{
										finish(pHarness, fDone,
											() =>
											{
												Expect(pError).to.equal(null);
												Expect(pResult.Status).to.equal(302);
												Expect(pResult.Headers.location).to.equal('/');

												let tmpSessions = Array.from(pHarness.auth.sessionStore.values());
												Expect(tmpSessions.length).to.equal(1);
												Expect(pResult.SetCookie[0]).to.equal(`SessionID=${tmpSessions[0].SessionID}; Path=/; HttpOnly; SameSite=Lax`);
											});
									});
							});
					}
				);
			}
		);
	}
);
