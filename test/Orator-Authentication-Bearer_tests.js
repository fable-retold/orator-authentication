/**
 * Bearer-token authentication tests for orator-authentication.
 */
const Chai = require('chai');
const Expect = Chai.expect;

const libFable = require('fable');
const libOrator = require('orator');
const libOratorAuthentication = require('../source/Orator-Authentication.js');

function makeAuth(pAuthOptions, fCallback)
{
	let tmpFable = new libFable({ Product: 'OratorAuthBearerTest', LogStreams: [{ level: 'error', streamtype: 'process.stdout' }] });
	tmpFable.serviceManager.addServiceType('Orator', libOrator);
	tmpFable.serviceManager.addServiceType('OratorAuthentication', libOratorAuthentication);
	let tmpOrator = tmpFable.serviceManager.instantiateServiceProvider('Orator', {});
	let tmpAuth = tmpFable.serviceManager.instantiateServiceProvider('OratorAuthentication', pAuthOptions || {});
	tmpOrator.startService(() => fCallback(tmpAuth));
}

suite('Orator Authentication - Bearer Tokens', () =>
{
	test('setTokenAuthenticator + resolveSessionForRequest are exposed', (fDone) =>
	{
		makeAuth({}, (pAuth) =>
		{
			Expect(pAuth.setTokenAuthenticator).to.be.a('function');
			Expect(pAuth.resolveSessionForRequest).to.be.a('function');
			return fDone();
		});
	});

	test('a valid Bearer token resolves to an ephemeral user session', (fDone) =>
	{
		makeAuth({ EnableBearerTokens: true }, (pAuth) =>
		{
			pAuth.setTokenAuthenticator((pToken, fCb) =>
				(pToken === 'good') ? fCb(null, { LoginID: 'svc', IDUser: 7, IDCustomer: 3 }) : fCb(null, null));
			pAuth.resolveSessionForRequest({ headers: { authorization: 'Bearer good' } }, (pErr, pSession) =>
			{
				Expect(pErr).to.not.be.ok;
				Expect(pSession).to.be.an('object');
				Expect(pSession.UserRecord.IDUser).to.equal(7);
				Expect(pSession.ViaToken).to.equal(true);
				Expect(pAuth.sessionStore.size).to.equal(0); // ephemeral, not stored
				return fDone();
			});
		});
	});

	test('an invalid Bearer token resolves to null', (fDone) =>
	{
		makeAuth({ EnableBearerTokens: true }, (pAuth) =>
		{
			pAuth.setTokenAuthenticator((pToken, fCb) => fCb(null, null));
			pAuth.resolveSessionForRequest({ headers: { authorization: 'Bearer nope' } }, (pErr, pSession) =>
			{
				Expect(pSession).to.equal(null);
				return fDone();
			});
		});
	});

	test('no cookie and no token resolves to null', (fDone) =>
	{
		makeAuth({ EnableBearerTokens: true }, (pAuth) =>
		{
			pAuth.setTokenAuthenticator((pToken, fCb) => fCb(null, { IDUser: 1 }));
			pAuth.resolveSessionForRequest({ headers: {} }, (pErr, pSession) =>
			{
				Expect(pSession).to.equal(null);
				return fDone();
			});
		});
	});

	test('bearer tokens are ignored when EnableBearerTokens is false (default)', (fDone) =>
	{
		makeAuth({}, (pAuth) =>
		{
			pAuth.setTokenAuthenticator((pToken, fCb) => fCb(null, { IDUser: 9 }));
			pAuth.resolveSessionForRequest({ headers: { authorization: 'Bearer good' } }, (pErr, pSession) =>
			{
				Expect(pSession).to.equal(null);
				return fDone();
			});
		});
	});

	test('getSessionForRequest returns the middleware-resolved UserSession', (fDone) =>
	{
		makeAuth({}, (pAuth) =>
		{
			Expect(pAuth.getSessionForRequest({ headers: {}, UserSession: { UserRecord: { IDUser: 42 } } }).UserRecord.IDUser).to.equal(42);
			Expect(pAuth.getSessionForRequest({ headers: {}, UserSession: null })).to.equal(null);
			return fDone();
		});
	});

	// Regression: a middleware may set an empty {} anonymous session (so a
	// downstream Object.keys() session marshaler does not choke on null).
	// getSessionForRequest must report that as null - a session with no
	// UserRecord is not authenticated - so callers like CheckSession do not
	// dereference UserRecord on it and crash.
	test('getSessionForRequest treats an empty {} session (no UserRecord) as null', (fDone) =>
	{
		makeAuth({}, (pAuth) =>
		{
			Expect(pAuth.getSessionForRequest({ headers: {}, UserSession: {} })).to.equal(null);
			Expect(pAuth.getSessionForRequest({ headers: {}, UserSession: { SessionID: 'x' } })).to.equal(null);
			return fDone();
		});
	});
});
