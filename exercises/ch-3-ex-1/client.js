var express = require("express");
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// authorization server information
// the client only needs to know about these two endpoints.
// the client doesn't need to know anything else about the server at all.
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information


/*
 * Add the client information in here
 */
var client = {
	// TODO: need values here to match that which is configured in authorizationServer.js
	"client_id": "oauth-client-1",
	// this approach cannot be used with a front end JavaScript client.
	// the secret would be in the brower and therefore provide no security benefit.
	"client_secret": "oauth-client-secret-1",
	"redirect_uris": ["http://localhost:9000/callback"]
};

// all we need to know at this point is where the protected resource is
var protectedResource = 'http://localhost:9002/resource';

var state = null;

var access_token = null;
var scope = null;

app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, scope: scope});
});

app.get('/authorize', function(req, res){

	/*
	 * Send the user to the authorization server
	 */
	let authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
		response_type: 'code',
		client_id: client.client_id,
		redirect_uri: client.redirect_uris[0]
	})
	console.log('GET','/authorize', 'REDIRECT', authorizeUrl);
	res.redirect(authorizeUrl)
});

// /callback is for the redirect_uri that is passed to the authorization server.
// the authorization server, if the flow is successful, will send a redirect
// to the browser. the browser will follow the redirect back to the client,
// which will pick up here.
app.get('/callback', function(req, res){

	/*
	 * Parse the response from the authorization server and get a token
	 */
	console.log('GET', '/callback')
	let code = req.query.code
	console.log('GET', '/callback', 'code', code)

	// and we will simply POST the authorization code to the /token endpoint
	// of the authorization server in order to get back a token.
	var form_data = qs.stringify({
		grant_type: 'authorization_code',
		code: code,
		// note that this is not going to be a redirect again, so this
		// value is not used.  however, the OAuth code specification requires
		// that the redirect_uri is sent again to the token request.
		// this is intended as a security measure to prevent a compromised redirect_uri
		// with a well-meaning client by injecting an auth code from one session to another.
		redirect_uri: client.redirect_uris[0]
	})
	console.log('GET', '/callback', 'form_data', form_data);

	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret)
	}
	console.log('GET', '/callback', 'headers', headers)

	// this might immediately create a POST? do we send it? not familar with this lib...
	let tokRes = request('POST', authServer.tokenEndpoint, {
		body: form_data,
		headers: headers
	})

	console.log('requesting access token for code %s', code)

	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		let body = JSON.parse(tokRes.getBody())
		console.log('GET', '/callback', 'token POST request response body', body)
		// store it as a global var
		access_token = body.access_token;
		console.log('GET', '/callback', 'got access token', access_token);
		res.render('index', {access_token: access_token, scope: scope})
	} else {
		res.render('error', {error: 'unable to fetch access token, server response: ' + tokenRes.statusCode})
		console.log('GET', '/callback', 'error')
	}

});

app.get('/fetch_resource', function(req, res) {

	/*
	 * Use the access token to call the resource server
	 */

});

var buildUrl = function(base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function(value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}
	let formatted = url.format(newUrl);
	console.log("buildUrl", base, options, hash);
	console.log("formatted:", formatted);
	return formatted
};

var encodeClientCredentials = function(clientId, clientSecret) {
	console.log("encodeClientCredentials()", clientId, clientSecret);
	let result = Buffer.from(querystring.escape(clientId) + ':' + querystring.escape(clientSecret)).toString('base64');
	console.log("result", result);
	return result
};

// the root route, this seems to match the top app.get("/") index route
app.use('/', express.static('files/client'));

// setup the server
var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
