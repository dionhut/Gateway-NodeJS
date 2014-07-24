/**
 * Module dependencies.
 */

var http = require('http')
  , util = require('util')
  , express = require('express')
  , xml2js = require('xml2js')
  , jwt = require('./oicjs/lib/JWT.js')
  , base64 = require('Base64')
  , request = require('request')
  , azure = require('azure')
  , routes = require('./routes');

var app = express();

// Configuration

app.configure(function(){
  app.use(express.bodyParser());
  app.use(express.cookieParser());
  app.use(express.methodOverride());
  app.use(app.router);
  app.use(express.static(__dirname + '/public'));
});

app.configure('development', function(){
  app.use(express.errorHandler({ dumpExceptions: true, showStack: true }));
});

app.configure('production', function(){
  app.use(express.errorHandler());
});

function validateJWT(wresult, success, error) {

	xml2js.parseString(wresult, function(err, result) {
		if(err) {
			throw new Error(err);
		}
		var token = base64.atob(result['t:RequestSecurityTokenResponse']['t:RequestedSecurityToken'][0]['wsse:BinarySecurityToken'][0]._);

		try {
			claims = jwt.jwt(jwt_options).init(token).getClaims();
			if(success) {
				success(claims);
			}
		}
		catch(ex) {
			console.error("Invalid JWT Token:" + ex);
			if(error) {
				error(ex);
			}
		}
	});
}

function reverseProxyService(serviceName, url, origReq, origRes) {
    var jar = request.jar();
    var cookie = request.cookie("GWAuth=" + origReq.cookies.GWAuth);
	jar.add(cookie);

    // append remainder of url to new url
	var tail = origReq.originalUrl;
	if (tail.charAt(0) == "/")
	    tail = tail.substr(1);
	var i = tail.indexOf("/");
	if (i > -1) {
	    tail = tail.substr(tail.indexOf("/"));
	    url = url.concat(tail);
	}
	console.log("--Proxy Url: %s", url);

	request({
		uri: url,
		method: 'GET',
		jar: jar
	}, function(error, response, content) {
	    if(!error) {
	        origRes.type(response.headers['content-type']);
	        if (response.headers['content-type'].match(/text.+html/)) {
                // Rewrite relative urls on web page to point to GW with ServiceName root
	            var regexRelative = /(<(a|area|base|form|frame|head|iframe|img|input|link|script)[^>]+(href|src)=")(?!https?::)(?!\/\/)(?!gw::)([^<>]+"[^<>]*>)/gi;
	            console.log("--Rewriting service webapp relative urls:%s", content.match(regexRelative));
	            content = content.replace(regexRelative, util.format("$1/%s/$4", serviceName));
            }
	        origRes.write(content);
			origRes.end();
		} else {
			console.error("--Error getting proxy request: %s", error);
			origRes.send(500);
		}
	});
};

function getFlight(serviceName, flightName, success, error) {
	console.log('--GetFlight: %s, %s', serviceName, flightName);
	tableService.queryEntity('Flight', serviceName, flightName, function(err, flightEntity) {
		if(!err) {
			console.log("--Flight found: %s, Url:%s", flightEntity.RowKey, flightEntity.Url);
			if(success) {
				success(flightEntity);
			}
		} else {
			if(error) {
				console.error("--Error GetFlight: %s", err);
	    		error(err);
	    	}
		}
	});
}

// Routes

app.get('/', routes.index);

app.get('/:serviceName*', function(req, res) {
	console.log("--Request Service:" + req.param('serviceName'));
	console.log("--Request url:" + req.originalUrl);

	var flight = null;
	if (req.query.flight) {
	    if (req.query.flight != "0") {
	        flight = req.query.flight;
	    } else {
	        res.clearCookie("GWFlight");
	    }
	} else if (req.cookies.GWFlight) {
	    flight = req.cookies.GWFlight;
	}

	// Order of redirect
	// 1. Specified flight
	// 2. Flight for user
	// 3. Default flight for service
	
	if(req.cookies.GWAuth) {
		validateJWT(req.cookies.GWAuth,
		function(claims) {
			console.log("--claims: %j", claims);
		    // Get service
			var query = azure.TableQuery
                .select()
                .from('Service')
                .where('RowKey eq ?', req.param('serviceName'));
			tableService.queryEntities(query, function (error, entities) {
			    if (!error && entities.length > 0) {
			        console.log("--Service Found: Application:%s, Service:%s, DefaultFlight:%s",
                        entities[0].PartitionKey, entities[0].RowKey, entities[0].DefaultFlight);

			    	if(flight) {
				    	// Get specified flight
			    	    getFlight(req.param('serviceName'), flight,
                            function (flightEntity) {
				    	        reverseProxyService(req.param('serviceName'), flightEntity.Url, req, res);
				    	        if (!req.cookies.GWFlight) {
				    	            res.cookie('GWFlight', flight);
				    	        }
				    	    },
			    		    function(error) {
					    	    res.send(404);
			    		    }
                        );
				    } else {
				    	// Get user flight
						tableService.queryEntity('UserFlight', req.param('serviceName'), claims.nameid, function(error, userFlightEntity) {
						    if(!error){
						        console.log("--User flight found: Service:%s, Flight:%s", userFlightEntity.PartitionKey, userFlightEntity.DefaultFlight);
						    	// Get flight url
						    	getFlight(req.param('serviceName'), userFlightEntity.DefaultFlight, function(flightEntity) {
						    	    reverseProxyService(req.param('serviceName'), flightEntity.Url, req, res);
					    		},
					    		function(error) {
							    	res.send(404);
						    	});
						    } else {
						    	// Get default flight for service
						        getFlight(req.param('serviceName'), entities[0].DefaultFlight, function (flightEntity) {
						            reverseProxyService(req.param('serviceName'), flightEntity.Url, req, res);
						        },
					    		function(error) {
							    	res.send(404);
						    	});
						    }
						});				    	
				    }
			    } else {
			    	// Service not found
			    	console.error("--Error Service %s not found: %s", req.param('serviceName'), error);
			    	res.send(404);
			    }
			});
		},
		function(error) {
			console.error("--Error Validating Token: %s", error);
			res.clearCookie("GWAuth");
			res.send(401);
		});

		res.clearCookie("GWReq");
	} else {
		console.log("--Redirecting to ACS");
		res.cookie('GWReq', req.originalUrl);
		res.redirect(ACSUrl);
	}
});

app.post('/auth', function(req, res) {
	console.log('ACS return');
	if(req.body.wresult && req.cookies && req.cookies.GWReq) {
		try {
			validateJWT(req.body.wresult);
			console.log("Redirecting from /auth -> originalUrl:%s", req.cookies.GWReq);
			res.cookie("GWAuth", req.body.wresult);
			res.redirect(req.cookies.GWReq);
		}
		catch(err) {
			console.error("Auth token not valid - %j", err);
			res.redirect('/autherror');
		}
	} else {
		console.error("Auth token or originalUrl not present");
		res.redirect('/autherror');
	}
});

app.all('/autherror', function(req, res) {
	console.log("ACS Error");
	res.send(401);
});

var ACSUrl = process.env.ACS_URL || 'https://dionhutgw.accesscontrol.windows.net:443/v2/wsfederation?wa=wsignin1.0&wtrealm=http%3a%2f%2flocalhost%3a3000%2f';
console.log("ACSUrl:%s", ACSUrl);

var jwt_options = {
    'iss': process.env.JWT_ISS || 'https://dionhutgw.accesscontrol.windows.net/',
    'aud': process.env.JWT_AUD || 'http://localhost:3000',
    'secret': process.env.JWT_SECRET || 'K1T4/0JeyQARTXpDXCaEF8Z1CZOi+iHj33hmHAmHoVs=',
    'supported_claims' : eval(process.env.JWT_SUPPORTED_CLAIMS || "['nameid', 'identityprovider']")
};
console.log("jwt_options:%j", jwt_options);

if(!process.env.AZURE_STORAGE_ACCOUNT) {
	process.env.AZURE_STORAGE_ACCOUNT = "tedgatewaynode";
}
console.log("AZURE_STORAGE_ACCOUNT: %s", process.env.AZURE_STORAGE_ACCOUNT);

if(!process.env.AZURE_STORAGE_ACCESS_KEY) {
	process.env.AZURE_STORAGE_ACCESS_KEY = "QgBfnyo8P3TGdtLqesCFD6UBfTJZgdi6dHS17CXb/wleRaD8X/x4IVEQkphP3GvfaKlR49RMg+xalEymBMRnZw==";
}
console.log("AZURE_STORAGE_ACCESS_KEY: %s", process.env.AZURE_STORAGE_ACCESS_KEY);

var tableService = azure.createTableService();
tableService.createTableIfNotExists('Service', function(error) {
});
tableService.createTableIfNotExists('Flight', function(error) {
});
tableService.createTableIfNotExists('UserFlight', function(error) {
});

var server = http.createServer(app).listen(process.env.port || 3000);
console.log("Express server listening on port %d in %s mode", server.address().port, app.settings.env);
