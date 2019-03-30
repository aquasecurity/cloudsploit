var https = require('https');
var httpSignature = require('http-signature');
var jsSHA = require('jssha');

function process( auth, options, callback) {

  // process request body
  var body;
  if (options.headers['content-type'] == 'application/x-www-form-urlencoded' )
    body = options.body;
  else
    body = JSON.stringify( options.body );
  delete options.body;

  // begin https request
  var request = https.request( options, handleResponse(callback) );

  // sing the headers
  sign( auth, request, body );

  // send the body and close the request
  request.write( body === undefined ? '' : body );
  request.end();
}

function sign( auth, request, body ) {
  var headersToSign = [ "host",  "date",  "(request-target)" ];

  // methodsThatRequireExtraHeaders ["POST", "PUT"];
  if(["POST","PUT"].indexOf(request.method.toUpperCase()) !== -1 ) 
  {
    body = body || ""; 
    request.setHeader("content-length", body.length);
    headersToSign = headersToSign.concat([ "content-type", "content-length" ]);

    if ( request.getHeader('content-type') != 'application/x-www-form-urlencoded' ){
      var shaObj = new jsSHA("SHA-256", "TEXT");
      shaObj.update(body);
      request.setHeader("x-content-sha256", shaObj.getHash('B64'));
      headersToSign = headersToSign.concat([ "x-content-sha256" ]);
    }
  }

  httpSignature.sign( request, { key: auth.privateKey,
                                 keyId: auth.tenancyId + "/" + 
                                        auth.userId + "/" + 
                                        auth.keyFingerprint,
                                 headers: headersToSign } );

  var newAuthHeaderValue = request.getHeader("Authorization").replace("Signature ", "Signature version=\"1\",");
  request.setHeader("Authorization", newAuthHeaderValue);
};

// generates a function to handle the https.request response object
function handleResponse( callback ) {
  return function(response) {
    var contentType = response.headers['content-type'];
    var JSONBody = '';
    var buffer = [];

    response.on( 'data', function(chunk) { 
      if( contentType == 'application/json' )
        JSONBody += chunk; 
      if( contentType == 'application/x-www-form-urlencoded' )
        buffer.push( Buffer.from( chunk, 'binary' ) );
      if( contentType == 'application/octet-stream' )
        buffer.push( chunk );
    });

    response.on( 'end', function() {
      if ( contentType == 'application/x-www-form-urlencoded' ||
           contentType == 'application/octet-stream' )
      {
        var binary = Buffer.concat(buffer);
        callback(binary);
      }
      if ( contentType == 'application/json' && JSONBody != '' )
        callback(JSON.parse( JSONBody ));
    });

  }
};


function buildHeaders( possibleHeaders, options, bString ){
  var headers = {};
  headers['content-type'] = bString ? 'application/x-www-form-urlencoded' : 'application/json';
  headers['user-agent'] = 'Mozilla/5.0';
  for( var i=0; i<possibleHeaders.length; i++ )
      if ( possibleHeaders[i].toLowerCase() in options )
        headers[possibleHeaders[i].toLowerCase()] = options[possibleHeaders[i]];
  return headers;
};

function buildQueryString( possibleQuery, options ){
  var query = '';
  for ( var i=0; i<possibleQuery.length; i++ )
    if ( possibleQuery[i] in options )
      query += (query=='' ? '?' : '&' ) + possibleQuery[i] + '=' + encodeURIComponent(options[possibleQuery[i]]);
  return query;
};

module.exports = {
  process: process,
  buildHeaders: buildHeaders,
  buildQueryString: buildQueryString
};
