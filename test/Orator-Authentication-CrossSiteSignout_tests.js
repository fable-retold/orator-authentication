/**
* Unit tests for the cross-site sign-out guard on Deauthenticate.
*
* SameSite=Lax keeps the session cookie off a cross-site POST, but a cross-site
* top-level GET still carries it, and the clearing cookie needs no incoming
* cookie at all. So without a check any site could sign users out. GET and
* POST /1.0/Deauthenticate now answer 403 (no session destroyed, no Set-Cookie)
* when the browser marks the request as cross-site: Sec-Fetch-Site decides when
* present, else an Origin is compared with Host / the first X-Forwarded-Host,
* else (no Origin: the CLI, curl, server-to-server) the request is allowed.
* AllowCrossSiteDeauthenticate (or the
* OratorAuthenticationAllowCrossSiteDeauthenticate fable setting) turns the
* guard off.
*
* The route-level tests run a real Restify server on an ephemeral port, because
* the IPC service server carries no request headers and no response headers.
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
const libOratorIPCSynthesizedResponse = require('orator/source/Orator-ServiceServer-IPC-SynthesizedResponse.js');
const libOratorAuthentication = require('../source/Orator-Authentication.js');

const defaultFableSettings = (
	{
		Product: 'OratorAuthentication-CrossSiteSignout-Tests',
		ProductVersion: '0.0.0',
		APIServerPort: 0
	});

const CLEAR_COOKIE = 'SessionID=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax';
const REFUSED_ERROR = 'Cross-site sign-out refused.';

/**
 * Build an OratorAuthentication instance (no server start).
 *
 * @param {object} pFableSettings - Fable settings to merge with defaults.
 * @param {object} pAuthOptions - Options for the OratorAuthentication instance.
 */
function makeAuth(pFableSettings, pAuthOptions)
{
	let tmpFableSettings = Object.assign({}, defaultFableSettings, pFableSettings || {});
	let tmpFable = new libFable(tmpFableSettings);

	tmpFable.serviceManager.addServiceType('Orator', libOrator);
	tmpFable.serviceManager.addServiceType('OratorAuthentication', libOratorAuthentication);
	tmpFable.serviceManager.instantiateServiceProvider('Orator', {});
	return tmpFable.serviceManager.instantiateServiceProvider('OratorAuthentication', pAuthOptions || {});
}

/**
 * Start a Fable + Orator (Restify) + OratorAuthentication harness on an
 * ephemeral port (each test connects the routes). A tiny query-string middleware
 * stands in for restify's queryParser plugin so the OAuth callback can read
 * ?state=.
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
 * Make a real HTTP request against the harness. Node's client adds a Host
 * header of 127.0.0.1:<port> unless pOptions.Headers sets one, and sends no
 * Origin or Sec-Fetch-Site unless asked to.
 *
 * @param {object} pHarness - From createRestifyHarness
 * @param {string} pMethod - GET / POST
 * @param {string} pPath - Request path
 * @param {object} pOptions - { Body: object, Cookie: string, Headers: object }
 * @param {Function} fCallback - (pError, { Status, Headers, SetCookie: [], Text, JSON })
 */
function httpRequest(pHarness, pMethod, pPath, pOptions, fCallback)
{
	let tmpOptions = pOptions || {};
	let tmpPayload = (`Body` in tmpOptions) ? JSON.stringify(tmpOptions.Body) : null;
	let tmpHeaders = Object.assign({}, tmpOptions.Headers || {});
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
 * Run fEach over pItems one after another, then call fComplete. An error from
 * any step stops the sequence.
 *
 * @param {Array} pItems - Items to visit in order
 * @param {Function} fEach - (pItem, fNextItem(pError))
 * @param {Function} fComplete - (pError)
 */
function runSequence(pItems, fEach, fComplete)
{
	let tmpIndex = 0;
	let fStep = (pError) =>
	{
		if (pError || (tmpIndex >= pItems.length))
		{
			return fComplete(pError || null);
		}
		let tmpItem = pItems[tmpIndex];
		tmpIndex++;
		return fEach(tmpItem, fStep);
	};
	return fStep();
}

/**
 * Sign in over HTTP, send one Deauthenticate with the given headers (and the
 * session cookie unless pSendCookie is false), then call CheckSession with the
 * session cookie to see whether the session survived.
 *
 * @param {object} pHarness - From createRestifyHarness
 * @param {string} pMethod - GET / POST for the Deauthenticate request
 * @param {object} pHeaders - Extra headers for the Deauthenticate request
 * @param {boolean} pSendCookie - Send the session cookie on Deauthenticate
 * @param {Function} fCallback - (pError, { SessionID, Login, Deauth, Check })
 */
function signInThenDeauthenticate(pHarness, pMethod, pHeaders, pSendCookie, fCallback)
{
	httpRequest(pHarness, 'POST', '/1.0/Authenticate', { Body: { UserName: 'operator', Password: 'pass' } },
		(pLoginError, pLogin) =>
		{
			if (pLoginError)
			{
				return fCallback(pLoginError);
			}
			let tmpSessionID = pLogin.JSON.SessionID;
			let tmpCookie = `SessionID=${tmpSessionID}`;

			httpRequest(pHarness, pMethod, '/1.0/Deauthenticate', { Cookie: (pSendCookie === false) ? null : tmpCookie, Headers: pHeaders },
				(pDeauthError, pDeauth) =>
				{
					if (pDeauthError)
					{
						return fCallback(pDeauthError);
					}

					httpRequest(pHarness, 'GET', '/1.0/CheckSession', { Cookie: tmpCookie },
						(pCheckError, pCheck) =>
						{
							if (pCheckError)
							{
								return fCallback(pCheckError);
							}
							return fCallback(null,
								{
									SessionID: tmpSessionID,
									Login: pLogin,
									Deauth: pDeauth,
									Check: pCheck
								});
						});
				});
		});
}

/**
 * The refused shape: 403, no Set-Cookie at all, the session still in the store
 * and still answering CheckSession.
 */
function expectRefused(pHarness, pResult, pCarriedSession, pLabel)
{
	let tmpLabel = pLabel || '';
	Expect(pResult.Deauth.Status, tmpLabel).to.equal(403);
	Expect(pResult.Deauth.Headers, tmpLabel).to.not.have.property('set-cookie');
	Expect(pResult.Deauth.JSON, tmpLabel).to.deep.equal({ LoggedIn: pCarriedSession, Error: REFUSED_ERROR });
	Expect(pHarness.auth.sessionStore.has(pResult.SessionID), tmpLabel).to.equal(true);
	Expect(pResult.Check.JSON.LoggedIn, tmpLabel).to.equal(true);
	Expect(pResult.Check.JSON.SessionID, tmpLabel).to.equal(pResult.SessionID);
}

/**
 * The signed-out shape: 200, the clearing cookie, the session gone.
 */
function expectSignedOut(pHarness, pResult, pLabel)
{
	let tmpLabel = pLabel || '';
	Expect(pResult.Deauth.Status, tmpLabel).to.equal(200);
	Expect(pResult.Deauth.JSON, tmpLabel).to.deep.equal({ LoggedIn: false });
	Expect(pResult.Deauth.SetCookie, tmpLabel).to.deep.equal([CLEAR_COOKIE]);
	Expect(pHarness.auth.sessionStore.has(pResult.SessionID), tmpLabel).to.equal(false);
	Expect(pResult.Check.JSON.LoggedIn, tmpLabel).to.equal(false);
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
	'Orator Authentication Cross-Site Sign-Out',
	() =>
	{
		suite
		(
			'Configuration',
			() =>
			{
				test
				(
					'AllowCrossSiteDeauthenticate defaults to false',
					() =>
					{
						Expect(makeAuth({}, {}).allowCrossSiteDeauthenticate).to.equal(false);
					}
				);

				test
				(
					'options set it, normalized to a boolean',
					() =>
					{
						Expect(makeAuth({}, { AllowCrossSiteDeauthenticate: true }).allowCrossSiteDeauthenticate).to.equal(true);
						Expect(makeAuth({}, { AllowCrossSiteDeauthenticate: 1 }).allowCrossSiteDeauthenticate).to.equal(true);
						Expect(makeAuth({}, { AllowCrossSiteDeauthenticate: false }).allowCrossSiteDeauthenticate).to.equal(false);
						Expect(makeAuth({}, { AllowCrossSiteDeauthenticate: 0 }).allowCrossSiteDeauthenticate).to.equal(false);
						Expect(makeAuth({}, { AllowCrossSiteDeauthenticate: undefined }).allowCrossSiteDeauthenticate).to.equal(false);
					}
				);

				test
				(
					'uses the fable settings fallback',
					() =>
					{
						Expect(makeAuth({ OratorAuthenticationAllowCrossSiteDeauthenticate: true }, {}).allowCrossSiteDeauthenticate).to.equal(true);
						Expect(makeAuth({ OratorAuthenticationAllowCrossSiteDeauthenticate: false }, {}).allowCrossSiteDeauthenticate).to.equal(false);
					}
				);

				test
				(
					'options take precedence over fable settings',
					() =>
					{
						Expect(makeAuth({ OratorAuthenticationAllowCrossSiteDeauthenticate: true }, { AllowCrossSiteDeauthenticate: false }).allowCrossSiteDeauthenticate).to.equal(false);
						Expect(makeAuth({ OratorAuthenticationAllowCrossSiteDeauthenticate: false }, { AllowCrossSiteDeauthenticate: true }).allowCrossSiteDeauthenticate).to.equal(true);
					}
				);

				test
				(
					'text values: only "true" and "1" (any case) turn the check off',
					() =>
					{
						let tmpOn = ['true', 'TRUE', ' True ', '1', ' 1 '];
						for (let i = 0; i < tmpOn.length; i++)
						{
							Expect(makeAuth({}, { AllowCrossSiteDeauthenticate: tmpOn[i] }).allowCrossSiteDeauthenticate, `option ${JSON.stringify(tmpOn[i])}`).to.equal(true);
							Expect(makeAuth({ OratorAuthenticationAllowCrossSiteDeauthenticate: tmpOn[i] }, {}).allowCrossSiteDeauthenticate, `setting ${JSON.stringify(tmpOn[i])}`).to.equal(true);
						}
						// !! would have turned every one of these on.
						let tmpOff = ['false', 'FALSE', ' false ', '0', '  ', 'yes', 'on', 'no', 'off', '2'];
						for (let i = 0; i < tmpOff.length; i++)
						{
							Expect(makeAuth({}, { AllowCrossSiteDeauthenticate: tmpOff[i] }).allowCrossSiteDeauthenticate, `option ${JSON.stringify(tmpOff[i])}`).to.equal(false);
							Expect(makeAuth({ OratorAuthenticationAllowCrossSiteDeauthenticate: tmpOff[i] }, {}).allowCrossSiteDeauthenticate, `setting ${JSON.stringify(tmpOff[i])}`).to.equal(false);
						}
						Expect(makeAuth({}, { AllowCrossSiteDeauthenticate: '' }).allowCrossSiteDeauthenticate, 'option ""').to.equal(false);
						Expect(makeAuth({ OratorAuthenticationAllowCrossSiteDeauthenticate: '' }, {}).allowCrossSiteDeauthenticate, 'setting ""').to.equal(false);
					}
				);

				test
				(
					'other non-boolean values leave the check on',
					() =>
					{
						let tmpValues = [2, -1, NaN, {}, [], ['true'], () => true, null];
						for (let i = 0; i < tmpValues.length; i++)
						{
							Expect(makeAuth({}, { AllowCrossSiteDeauthenticate: tmpValues[i] }).allowCrossSiteDeauthenticate, `value ${i}`).to.equal(false);
						}
					}
				);

				test
				(
					'a ${ENV|false} templated fable setting is off unless the variable says true',
					() =>
					{
						let tmpName = 'ORATOR_AUTH_TEST_XSITE_SIGNOUT';
						let tmpHadValue = Object.prototype.hasOwnProperty.call(process.env, tmpName);
						let tmpOldValue = process.env[tmpName];
						let tmpSetting = { OratorAuthenticationAllowCrossSiteDeauthenticate: '${' + tmpName + '|false}' };
						try
						{
							// Unset: the default text 'false' (a string) is used.
							delete process.env[tmpName];
							Expect(makeAuth(tmpSetting, {}).allowCrossSiteDeauthenticate, 'unset').to.equal(false);

							process.env[tmpName] = 'false';
							Expect(makeAuth(tmpSetting, {}).allowCrossSiteDeauthenticate, 'false').to.equal(false);

							process.env[tmpName] = '0';
							Expect(makeAuth(tmpSetting, {}).allowCrossSiteDeauthenticate, '0').to.equal(false);

							process.env[tmpName] = 'true';
							Expect(makeAuth(tmpSetting, {}).allowCrossSiteDeauthenticate, 'true').to.equal(true);

							// An option read straight from the environment behaves the same.
							process.env[tmpName] = 'false';
							Expect(makeAuth({}, { AllowCrossSiteDeauthenticate: process.env[tmpName] }).allowCrossSiteDeauthenticate, 'option from env').to.equal(false);
						}
						finally
						{
							if (tmpHadValue)
							{
								process.env[tmpName] = tmpOldValue;
							}
							else
							{
								delete process.env[tmpName];
							}
						}
					}
				);

				test
				(
					'_normalizeAllowCrossSiteDeauthenticate warns only on values it does not recognize',
					() =>
					{
						let tmpAuth = makeAuth({}, {});
						let tmpQuiet = [true, false, 1, 0, undefined, null, 'true', 'false', '1', '0', '', ' TRUE '];
						for (let i = 0; i < tmpQuiet.length; i++)
						{
							Expect(tmpAuth._normalizeAllowCrossSiteDeauthenticate(tmpQuiet[i]).Warning, `value ${i}`).to.equal(null);
						}

						let tmpYes = tmpAuth._normalizeAllowCrossSiteDeauthenticate('yes');
						Expect(tmpYes.Value).to.equal(false);
						Expect(tmpYes.Warning).to.include('"yes"');
						Expect(tmpYes.Warning).to.include('stays refused');

						let tmpTwo = tmpAuth._normalizeAllowCrossSiteDeauthenticate(2);
						Expect(tmpTwo.Value).to.equal(false);
						Expect(tmpTwo.Warning).to.include('value 2 ');

						// A value that cannot be turned into text does not throw.
						let tmpUnprintable = tmpAuth._normalizeAllowCrossSiteDeauthenticate({ toString: () => { throw new Error('boom'); } });
						Expect(tmpUnprintable.Value).to.equal(false);
						Expect(tmpUnprintable.Warning).to.include('[object]');
					}
				);

				test
				(
					'the constructor logs the warning for an unrecognized value',
					() =>
					{
						let tmpFable = new libFable(Object.assign({}, defaultFableSettings));
						let tmpLines = [];
						let tmpOriginalWarn = tmpFable.log.warn;
						tmpFable.log.warn = (pMessage) => { tmpLines.push(String(pMessage)); };
						let tmpAuth;
						try
						{
							tmpFable.serviceManager.addServiceType('Orator', libOrator);
							tmpFable.serviceManager.addServiceType('OratorAuthentication', libOratorAuthentication);
							tmpFable.serviceManager.instantiateServiceProvider('Orator', {});
							tmpAuth = tmpFable.serviceManager.instantiateServiceProvider('OratorAuthentication', { AllowCrossSiteDeauthenticate: 'yes' });
						}
						finally
						{
							tmpFable.log.warn = tmpOriginalWarn;
						}
						Expect(tmpAuth.allowCrossSiteDeauthenticate).to.equal(false);
						Expect(tmpLines.length).to.equal(1);
						Expect(tmpLines[0]).to.include('AllowCrossSiteDeauthenticate');
					}
				);
			}
		);

		suite
		(
			'_isCrossSiteRequest',
			() =>
			{
				let tmpAuth = null;

				suiteSetup
				(
					() =>
					{
						tmpAuth = makeAuth({}, {});
					}
				);

				test
				(
					'a missing request or headers object is not cross-site',
					() =>
					{
						Expect(tmpAuth._isCrossSiteRequest(undefined)).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest(null)).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({})).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: null })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: {} })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: 'origin: https://evil.example' })).to.equal(false);
					}
				);

				test
				(
					'Sec-Fetch-Site decides alone, case-insensitively',
					() =>
					{
						Expect(tmpAuth._isCrossSiteRequest({ headers: { 'sec-fetch-site': 'cross-site' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { 'sec-fetch-site': 'Cross-Site' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { 'sec-fetch-site': ' CROSS-SITE ' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { 'sec-fetch-site': 'same-origin' } })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { 'sec-fetch-site': 'same-site' } })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { 'sec-fetch-site': 'none' } })).to.equal(false);

						// A same-origin Sec-Fetch-Site wins over a foreign Origin, and a
						// cross-site one wins over a matching Origin.
						Expect(tmpAuth._isCrossSiteRequest({ headers: { 'sec-fetch-site': 'same-origin', origin: 'https://evil.example', host: 'app.example.com' } })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { 'sec-fetch-site': 'cross-site', origin: 'https://app.example.com', host: 'app.example.com' } })).to.equal(true);
					}
				);

				test
				(
					'a blank Sec-Fetch-Site falls through to the Origin check',
					() =>
					{
						Expect(tmpAuth._isCrossSiteRequest({ headers: { 'sec-fetch-site': '  ', origin: 'https://evil.example', host: 'app.example.com' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { 'sec-fetch-site': '', origin: 'https://app.example.com', host: 'app.example.com' } })).to.equal(false);
					}
				);

				test
				(
					'no Origin (and no Sec-Fetch-Site) is not cross-site',
					() =>
					{
						Expect(tmpAuth._isCrossSiteRequest({ headers: { host: 'app.example.com' } })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { host: 'app.example.com', origin: undefined } })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { host: 'app.example.com', origin: null } })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { host: 'app.example.com', origin: '' } })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: '' } })).to.equal(false);
					}
				);

				test
				(
					'an Origin matching the Host header is not cross-site',
					() =>
					{
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'https://app.example.com', host: 'app.example.com' } })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'http://localhost:8080', host: 'localhost:8080' } })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'http://[::1]:8080', host: '[::1]:8080' } })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'https://APP.Example.com', host: ' app.EXAMPLE.com ' } })).to.equal(false);
					}
				);

				test
				(
					'a default port is ignored on either side',
					() =>
					{
						// Explicit default port on the Host header.
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'https://app.example.com', host: 'app.example.com:443' } })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'http://app.example.com', host: 'app.example.com:80' } })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'https://app.example.com', 'x-forwarded-host': 'app.example.com:443' } })).to.equal(false);
						// Explicit default port on the Origin.
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'https://app.example.com:443', host: 'app.example.com' } })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'http://app.example.com:80', host: 'app.example.com' } })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'https://app.example.com:443', host: 'app.example.com:443' } })).to.equal(false);
					}
				);

				test
				(
					'only the default port of the Origin scheme is ignored',
					() =>
					{
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'http://app.example.com', host: 'app.example.com:443' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'https://app.example.com', host: 'app.example.com:80' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'https://app.example.com', host: 'app.example.com:8443' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'https://app.example.com:8443', host: 'app.example.com:8443' } })).to.equal(false);
						// A port written on the header must match the Origin's.
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'http://app.example.com:8080', host: 'app.example.com:8081' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'https://app.example.com:8443', host: 'app.example.com:443' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'http://app.example.com:8080', host: 'app.example.com:80' } })).to.equal(true);
					}
				);

				test
				(
					'a header with no port matches on the host name (a proxy dropped the port)',
					() =>
					{
						// nginx `proxy_set_header Host $host` in front of a non-default port.
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'http://juicebox:8080', host: 'juicebox' } })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'https://app.example.com:8443', host: 'APP.example.com' } })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'http://juicebox:8080', host: '10.0.0.5:3000', 'x-forwarded-host': 'juicebox' } })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'http://[::1]:8080', host: '[::1]' } })).to.equal(false);
						// The host name itself must still match.
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'http://evil.example:8080', host: 'juicebox' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'http://juicebox.evil.example:8080', host: 'juicebox' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'http://[::2]:8080', host: '[::1]' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'http://juicebox:8080', host: 'juicebox:' } })).to.equal(true);
					}
				);

				test
				(
					'a trailing dot on either host name is ignored',
					() =>
					{
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'https://app.example.com.', host: 'app.example.com' } })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'https://app.example.com', host: 'app.example.com.' } })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'https://app.example.com.:8443', host: 'app.example.com.:8443' } })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'https://app.example.com.', host: 'app.example.com..' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'https://app.example.com', host: '.' } })).to.equal(true);
					}
				);

				test
				(
					'_hostHeaderMatchesOrigin never throws and rejects empty or unreadable values',
					() =>
					{
						let tmpOrigin = new URL('https://app.example.com');
						Expect(tmpAuth._hostHeaderMatchesOrigin('app.example.com', tmpOrigin)).to.equal(true);
						Expect(tmpAuth._hostHeaderMatchesOrigin('app.example.com:0443', tmpOrigin)).to.equal(true);
						Expect(tmpAuth._hostHeaderMatchesOrigin('', tmpOrigin)).to.equal(false);
						Expect(tmpAuth._hostHeaderMatchesOrigin('   ', tmpOrigin)).to.equal(false);
						Expect(tmpAuth._hostHeaderMatchesOrigin(undefined, tmpOrigin)).to.equal(false);
						Expect(tmpAuth._hostHeaderMatchesOrigin({ toString: () => { throw new Error('boom'); } }, tmpOrigin)).to.equal(false);
						Expect(tmpAuth._hostHeaderMatchesOrigin('app.example.com', null)).to.equal(false);
					}
				);

				test
				(
					'only the first X-Forwarded-Host value counts',
					() =>
					{
						let tmpHeaders = { host: '10.0.0.5:3000', 'x-forwarded-host': ' app.example.com , internal.example:8080' };
						Expect(tmpAuth._isCrossSiteRequest({ headers: Object.assign({ origin: 'https://app.example.com' }, tmpHeaders) })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: Object.assign({ origin: 'http://internal.example:8080' }, tmpHeaders) })).to.equal(true);
						// The Host header still counts beside X-Forwarded-Host.
						Expect(tmpAuth._isCrossSiteRequest({ headers: Object.assign({ origin: 'http://10.0.0.5:3000' }, tmpHeaders) })).to.equal(false);
						// X-Forwarded-Host alone (no Host header).
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'https://app.example.com', 'x-forwarded-host': 'APP.example.com' } })).to.equal(false);
					}
				);

				test
				(
					'a foreign, null or unparseable Origin is cross-site',
					() =>
					{
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'https://evil.example', host: 'app.example.com' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'https://app.example.com.evil.example', host: 'app.example.com' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'https://other.example.com', host: 'app.example.com' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'null', host: 'app.example.com' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'not a url', host: 'app.example.com' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: '   ', host: 'app.example.com' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'app.example.com', host: 'app.example.com' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'ftp://app.example.com', host: 'app.example.com' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'file:///etc/passwd', host: 'app.example.com' } })).to.equal(true);
						// An Origin with no Host or X-Forwarded-Host to compare against.
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'https://app.example.com' } })).to.equal(true);
					}
				);

				test
				(
					'never throws on garbage; cross-site only when an Origin was present',
					() =>
					{
						let tmpThrowingValue = { toString: () => { throw new Error('boom'); } };

						// Every header read throws: no Origin can be seen, so not cross-site.
						let tmpThrowingHeaders = new Proxy({}, { get: () => { throw new Error('boom'); } });
						Expect(tmpAuth._isCrossSiteRequest({ headers: tmpThrowingHeaders })).to.equal(false);

						// An Origin that cannot be read as text.
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: tmpThrowingValue, host: 'app.example.com' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: Object.create(null), host: 'app.example.com' } })).to.equal(true);

						// An unreadable Sec-Fetch-Site falls through to the Origin rule.
						Expect(tmpAuth._isCrossSiteRequest({ headers: { 'sec-fetch-site': tmpThrowingValue } })).to.equal(false);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { 'sec-fetch-site': tmpThrowingValue, origin: 'https://evil.example', host: 'app.example.com' } })).to.equal(true);

						// Unreadable Host / X-Forwarded-Host never match.
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 'https://app.example.com', host: tmpThrowingValue, 'x-forwarded-host': tmpThrowingValue } })).to.equal(true);

						// Non-string values (a duplicated header joined into an array).
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: ['https://app.example.com', 'https://evil.example'], host: 'app.example.com' } })).to.equal(true);
						Expect(tmpAuth._isCrossSiteRequest({ headers: { origin: 42, host: 'app.example.com' } })).to.equal(true);
					}
				);
			}
		);

		suite
		(
			'Handler',
			() =>
			{
				test
				(
					'refuses with a body on the IPC synthesized response, which has a body-only send()',
					() =>
					{
						let tmpAuth = makeAuth({}, {});
						let tmpSession = tmpAuth._createSession({ LoginID: 'ipc-user', IDUser: 7 });
						let tmpResponse = new libOratorIPCSynthesizedResponse({}, () => {}, 'test-guid');
						let tmpNextCalled = false;

						tmpAuth._handleDeauthentication(
							{ headers: { 'sec-fetch-site': 'cross-site', cookie: `SessionID=${tmpSession.SessionID}` } },
							tmpResponse,
							() => { tmpNextCalled = true; });

						Expect(tmpNextCalled).to.equal(true);
						Expect(tmpResponse.statusCode).to.equal(403);
						Expect(JSON.parse(tmpResponse.responseData)).to.deep.equal({ LoggedIn: true, Error: REFUSED_ERROR });
						Expect(tmpAuth.sessionStore.has(tmpSession.SessionID)).to.equal(true);
					}
				);

				test
				(
					'a request with no headers (as the IPC server builds them) still signs out',
					() =>
					{
						let tmpAuth = makeAuth({}, {});
						let tmpResponse = new libOratorIPCSynthesizedResponse({}, () => {}, 'test-guid');
						let tmpNextCalled = false;

						tmpAuth._handleDeauthentication({ method: 'GET', url: '/1.0/Deauthenticate' }, tmpResponse, () => { tmpNextCalled = true; });

						Expect(tmpNextCalled).to.equal(true);
						Expect(tmpResponse.statusCode).to.equal(undefined);
						Expect(JSON.parse(tmpResponse.responseData)).to.deep.equal({ LoggedIn: false });
					}
				);

				test
				(
					'logs one info line naming only the deciding signal',
					() =>
					{
						let tmpAuth = makeAuth({}, {});
						let tmpSession = tmpAuth._createSession({ LoginID: 'log-user', IDUser: 7 });
						let tmpLines = [];
						let tmpOriginalInfo = tmpAuth.log.info;
						tmpAuth.log.info = (pMessage) => { tmpLines.push(String(pMessage)); };

						let tmpMockResponse = { send: () => {}, setHeader: () => { throw new Error('no header may be set'); } };
						try
						{
							tmpAuth._handleDeauthentication(
								{ headers: { 'sec-fetch-site': 'cross-site', origin: 'https://evil.example', cookie: `SessionID=${tmpSession.SessionID}` } },
								tmpMockResponse, () => {});
							tmpAuth._handleDeauthentication(
								{ headers: { origin: 'https://evil.example', host: 'app.example.com', cookie: `SessionID=${tmpSession.SessionID}` } },
								tmpMockResponse, () => {});
						}
						finally
						{
							tmpAuth.log.info = tmpOriginalInfo;
						}

						Expect(tmpLines.length).to.equal(2);
						Expect(tmpLines[0]).to.include('cross-site Deauthenticate');
						Expect(tmpLines[0]).to.include('Sec-Fetch-Site');
						Expect(tmpLines[1]).to.include('cross-site Deauthenticate');
						Expect(tmpLines[1]).to.include('Origin');
						for (let i = 0; i < tmpLines.length; i++)
						{
							Expect(tmpLines[i]).to.not.include(tmpSession.SessionID);
							Expect(tmpLines[i]).to.not.include('evil.example');
							Expect(tmpLines[i]).to.not.include('app.example.com');
						}
						Expect(tmpAuth.sessionStore.has(tmpSession.SessionID)).to.equal(true);
					}
				);
			}
		);

		suite
		(
			'Real HTTP: refused',
			() =>
			{
				test
				(
					'GET /1.0/Deauthenticate with Sec-Fetch-Site: cross-site is refused and the session survives',
					(fDone) =>
					{
						createRestifyHarness(null, null,
							(pHarness) =>
							{
								pHarness.auth.connectRoutes();
								signInThenDeauthenticate(pHarness, 'GET', { 'Sec-Fetch-Site': 'cross-site' }, true,
									(pError, pResult) =>
									{
										finish(pHarness, fDone,
											() =>
											{
												Expect(pError).to.equal(null);
												expectRefused(pHarness, pResult, true);
											});
									});
							});
					}
				);

				test
				(
					'POST /1.0/Deauthenticate with Sec-Fetch-Site: cross-site is refused and the session survives',
					(fDone) =>
					{
						createRestifyHarness(null, null,
							(pHarness) =>
							{
								pHarness.auth.connectRoutes();
								signInThenDeauthenticate(pHarness, 'POST', { 'Sec-Fetch-Site': 'cross-site' }, true,
									(pError, pResult) =>
									{
										finish(pHarness, fDone,
											() =>
											{
												Expect(pError).to.equal(null);
												expectRefused(pHarness, pResult, true);
											});
									});
							});
					}
				);

				test
				(
					'a cross-site POST with no cookie (what Lax sends) is refused with no clearing cookie',
					(fDone) =>
					{
						createRestifyHarness(null, null,
							(pHarness) =>
							{
								pHarness.auth.connectRoutes();
								signInThenDeauthenticate(pHarness, 'POST', { 'Sec-Fetch-Site': 'cross-site' }, false,
									(pError, pResult) =>
									{
										finish(pHarness, fDone,
											() =>
											{
												Expect(pError).to.equal(null);
												expectRefused(pHarness, pResult, false);
											});
									});
							});
					}
				);

				test
				(
					'uppercase Sec-Fetch-Site: Cross-Site is refused',
					(fDone) =>
					{
						createRestifyHarness(null, null,
							(pHarness) =>
							{
								pHarness.auth.connectRoutes();
								signInThenDeauthenticate(pHarness, 'GET', { 'Sec-Fetch-Site': 'Cross-Site' }, true,
									(pError, pResult) =>
									{
										finish(pHarness, fDone,
											() =>
											{
												Expect(pError).to.equal(null);
												expectRefused(pHarness, pResult, true);
											});
									});
							});
					}
				);

				test
				(
					'Origin-only requests with a foreign, null or unparseable Origin are refused',
					(fDone) =>
					{
						createRestifyHarness(null, null,
							(pHarness) =>
							{
								pHarness.auth.connectRoutes();
								let tmpCases =
								[
									{ Method: 'GET', Origin: 'https://evil.example' },
									{ Method: 'POST', Origin: 'https://evil.example' },
									{ Method: 'GET', Origin: `http://127.0.0.2:${pHarness.port}` },
									{ Method: 'GET', Origin: 'null' },
									{ Method: 'POST', Origin: 'null' },
									{ Method: 'GET', Origin: 'not a url' },
									{ Method: 'GET', Origin: 'ftp://127.0.0.1' },
									// A port written on the Host header must match the Origin's.
									{ Method: 'POST', Origin: 'http://juicebox:8080', Host: 'juicebox:8081' },
									// A port-less Host still needs the same host name.
									{ Method: 'POST', Origin: 'http://evil.example:8080', Host: 'juicebox' }
								];
								let tmpResults = [];
								runSequence(tmpCases,
									(pCase, fNextCase) =>
									{
										let tmpHeaders = { Origin: pCase.Origin };
										if (pCase.Host)
										{
											tmpHeaders.Host = pCase.Host;
										}
										signInThenDeauthenticate(pHarness, pCase.Method, tmpHeaders, true,
											(pError, pResult) =>
											{
												if (!pError)
												{
													tmpResults.push({ Case: pCase, Result: pResult });
												}
												return fNextCase(pError);
											});
									},
									(pError) =>
									{
										finish(pHarness, fDone,
											() =>
											{
												Expect(pError).to.equal(null);
												Expect(tmpResults.length).to.equal(tmpCases.length);
												for (let i = 0; i < tmpResults.length; i++)
												{
													expectRefused(pHarness, tmpResults[i].Result, true, `${tmpResults[i].Case.Method} Origin ${tmpResults[i].Case.Origin}`);
												}
											});
									});
							});
					}
				);

				test
				(
					'the text "false" (as ${ENV|false} templating produces) keeps refusing',
					(fDone) =>
					{
						createRestifyHarness({ OratorAuthenticationAllowCrossSiteDeauthenticate: 'false' }, null,
							(pHarness) =>
							{
								pHarness.auth.connectRoutes();
								signInThenDeauthenticate(pHarness, 'GET', { 'Sec-Fetch-Site': 'cross-site' }, true,
									(pError, pResult) =>
									{
										finish(pHarness, fDone,
											() =>
											{
												Expect(pError).to.equal(null);
												Expect(pHarness.auth.allowCrossSiteDeauthenticate).to.equal(false);
												expectRefused(pHarness, pResult, true);
											});
									});
							});
					}
				);

				test
				(
					'options beat fable settings: settings allow, options refuse',
					(fDone) =>
					{
						createRestifyHarness({ OratorAuthenticationAllowCrossSiteDeauthenticate: true }, { AllowCrossSiteDeauthenticate: false },
							(pHarness) =>
							{
								pHarness.auth.connectRoutes();
								signInThenDeauthenticate(pHarness, 'GET', { 'Sec-Fetch-Site': 'cross-site' }, true,
									(pError, pResult) =>
									{
										finish(pHarness, fDone,
											() =>
											{
												Expect(pError).to.equal(null);
												expectRefused(pHarness, pResult, true);
											});
									});
							});
					}
				);
			}
		);

		suite
		(
			'Real HTTP: allowed',
			() =>
			{
				test
				(
					'Sec-Fetch-Site same-origin, same-site and none sign out (GET and POST)',
					(fDone) =>
					{
						createRestifyHarness(null, null,
							(pHarness) =>
							{
								pHarness.auth.connectRoutes();
								let tmpCases = [];
								let tmpValues = ['same-origin', 'same-site', 'none'];
								for (let i = 0; i < tmpValues.length; i++)
								{
									tmpCases.push({ Method: 'GET', FetchSite: tmpValues[i] });
									tmpCases.push({ Method: 'POST', FetchSite: tmpValues[i] });
								}
								let tmpResults = [];
								runSequence(tmpCases,
									(pCase, fNextCase) =>
									{
										signInThenDeauthenticate(pHarness, pCase.Method, { 'Sec-Fetch-Site': pCase.FetchSite }, true,
											(pError, pResult) =>
											{
												if (!pError)
												{
													tmpResults.push({ Case: pCase, Result: pResult });
												}
												return fNextCase(pError);
											});
									},
									(pError) =>
									{
										finish(pHarness, fDone,
											() =>
											{
												Expect(pError).to.equal(null);
												Expect(tmpResults.length).to.equal(tmpCases.length);
												for (let i = 0; i < tmpResults.length; i++)
												{
													expectSignedOut(pHarness, tmpResults[i].Result, `${tmpResults[i].Case.Method} ${tmpResults[i].Case.FetchSite}`);
												}
											});
									});
							});
					}
				);

				test
				(
					'no Origin and no Sec-Fetch-Site (the CLI, curl) signs out',
					(fDone) =>
					{
						createRestifyHarness(null, null,
							(pHarness) =>
							{
								pHarness.auth.connectRoutes();
								signInThenDeauthenticate(pHarness, 'GET', {}, true,
									(pGetError, pGetResult) =>
									{
										signInThenDeauthenticate(pHarness, 'POST', {}, true,
											(pPostError, pPostResult) =>
											{
												finish(pHarness, fDone,
													() =>
													{
														Expect(pGetError).to.equal(null);
														Expect(pPostError).to.equal(null);
														expectSignedOut(pHarness, pGetResult, 'GET');
														expectSignedOut(pHarness, pPostResult, 'POST');
													});
											});
									});
							});
					}
				);

				test
				(
					'an Origin matching the Host header signs out',
					(fDone) =>
					{
						createRestifyHarness(null, null,
							(pHarness) =>
							{
								pHarness.auth.connectRoutes();
								let tmpCases =
								[
									// The Host header Node's client sends (127.0.0.1:<port>).
									{ Method: 'POST', Headers: { Origin: `http://127.0.0.1:${pHarness.port}` } },
									// A named host, with the default port written out on the Host header.
									{ Method: 'GET', Headers: { Host: 'app.example.com:443', Origin: 'https://app.example.com' } },
									{ Method: 'POST', Headers: { Host: 'APP.example.com', Origin: 'http://app.example.com:80' } },
									// Behind nginx `proxy_set_header Host $host` on a non-default
									// port over plain http: no Sec-Fetch-Site, and the proxy dropped
									// the port from Host.
									{ Method: 'POST', Headers: { Host: 'juicebox', Origin: 'http://juicebox:8080' } },
									// The same proxy also strips a trailing dot from the host name.
									{ Method: 'POST', Headers: { Host: 'app.example.com', Origin: 'https://app.example.com.' } }
								];
								let tmpResults = [];
								runSequence(tmpCases,
									(pCase, fNextCase) =>
									{
										signInThenDeauthenticate(pHarness, pCase.Method, pCase.Headers, true,
											(pError, pResult) =>
											{
												if (!pError)
												{
													tmpResults.push({ Case: pCase, Result: pResult });
												}
												return fNextCase(pError);
											});
									},
									(pError) =>
									{
										finish(pHarness, fDone,
											() =>
											{
												Expect(pError).to.equal(null);
												Expect(tmpResults.length).to.equal(tmpCases.length);
												for (let i = 0; i < tmpResults.length; i++)
												{
													expectSignedOut(pHarness, tmpResults[i].Result, JSON.stringify(tmpResults[i].Case.Headers));
												}
											});
									});
							});
					}
				);

				test
				(
					'an Origin matching the first X-Forwarded-Host signs out; a later entry does not count',
					(fDone) =>
					{
						createRestifyHarness(null, null,
							(pHarness) =>
							{
								pHarness.auth.connectRoutes();
								signInThenDeauthenticate(pHarness, 'POST',
									{ Origin: 'https://app.example.com', 'X-Forwarded-Host': 'app.example.com, edge.internal' }, true,
									(pFirstError, pFirstResult) =>
									{
										signInThenDeauthenticate(pHarness, 'POST',
											{ Origin: 'https://edge.internal', 'X-Forwarded-Host': 'app.example.com, edge.internal' }, true,
											(pSecondError, pSecondResult) =>
											{
												finish(pHarness, fDone,
													() =>
													{
														Expect(pFirstError).to.equal(null);
														Expect(pSecondError).to.equal(null);
														expectSignedOut(pHarness, pFirstResult, 'first X-Forwarded-Host');
														expectRefused(pHarness, pSecondResult, true, 'second X-Forwarded-Host');
													});
											});
									});
							});
					}
				);

				test
				(
					'AllowCrossSiteDeauthenticate: true lets a cross-site request sign out',
					(fDone) =>
					{
						createRestifyHarness(null, { AllowCrossSiteDeauthenticate: true },
							(pHarness) =>
							{
								pHarness.auth.connectRoutes();
								signInThenDeauthenticate(pHarness, 'GET', { 'Sec-Fetch-Site': 'cross-site' }, true,
									(pGetError, pGetResult) =>
									{
										signInThenDeauthenticate(pHarness, 'POST', { Origin: 'https://evil.example' }, true,
											(pPostError, pPostResult) =>
											{
												finish(pHarness, fDone,
													() =>
													{
														Expect(pGetError).to.equal(null);
														Expect(pPostError).to.equal(null);
														expectSignedOut(pHarness, pGetResult, 'GET Sec-Fetch-Site');
														expectSignedOut(pHarness, pPostResult, 'POST Origin');
													});
											});
									});
							});
					}
				);

				test
				(
					'the fable setting OratorAuthenticationAllowCrossSiteDeauthenticate lets a cross-site request sign out',
					(fDone) =>
					{
						createRestifyHarness({ OratorAuthenticationAllowCrossSiteDeauthenticate: true }, null,
							(pHarness) =>
							{
								pHarness.auth.connectRoutes();
								signInThenDeauthenticate(pHarness, 'GET', { 'Sec-Fetch-Site': 'cross-site' }, true,
									(pError, pResult) =>
									{
										finish(pHarness, fDone,
											() =>
											{
												Expect(pError).to.equal(null);
												expectSignedOut(pHarness, pResult);
											});
									});
							});
					}
				);
			}
		);

		suite
		(
			'Real HTTP: other routes are not guarded',
			() =>
			{
				test
				(
					'cross-site CheckSession and Authenticate still answer normally',
					(fDone) =>
					{
						createRestifyHarness(null, null,
							(pHarness) =>
							{
								pHarness.auth.connectRoutes();
								httpRequest(pHarness, 'POST', '/1.0/Authenticate',
									{ Body: { UserName: 'operator', Password: 'pass' }, Headers: { 'Sec-Fetch-Site': 'cross-site' } },
									(pLoginError, pLogin) =>
									{
										if (pLoginError)
										{
											return finish(pHarness, fDone, () => { throw pLoginError; });
										}
										httpRequest(pHarness, 'GET', '/1.0/CheckSession',
											{ Cookie: `SessionID=${pLogin.JSON.SessionID}`, Headers: { 'Sec-Fetch-Site': 'cross-site' } },
											(pError, pCheck) =>
											{
												finish(pHarness, fDone,
													() =>
													{
														Expect(pError).to.equal(null);
														Expect(pLogin.Status).to.equal(200);
														Expect(pLogin.JSON.LoggedIn).to.equal(true);
														Expect(pLogin.SetCookie.length).to.equal(1);
														Expect(pCheck.Status).to.equal(200);
														Expect(pCheck.JSON.LoggedIn).to.equal(true);
														Expect(pCheck.JSON.SessionID).to.equal(pLogin.JSON.SessionID);
													});
											});
									});
							});
					}
				);

				test
				(
					'the OAuth callback (a cross-site top-level GET from the provider) still signs in',
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

								let tmpState = 'cross-site-oauth-state';
								pHarness.auth._storeOAuthState(tmpState,
									{
										CodeVerifier: 'test-code-verifier',
										Nonce: 'test-nonce',
										Provider: 'mock'
									});

								httpRequest(pHarness, 'GET', `/1.0/OAuth/Callback/mock?code=mock-code&state=${tmpState}`,
									{ Headers: { 'Sec-Fetch-Site': 'cross-site' } },
									(pError, pResult) =>
									{
										finish(pHarness, fDone,
											() =>
											{
												Expect(pError).to.equal(null);
												Expect(pResult.Status).to.equal(302);
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
