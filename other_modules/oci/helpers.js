var https = require('https');
var signature = require('http-signature');

function call(OracleConfig, options, callback) {
    var body = JSON.stringify(options.body);
    delete options.body;
    var respBodyArr =[];
    var newOptions = JSON.parse(JSON.stringify(options));
    var originalPath = options.path;

    var makeCall = function(innerOptions) {
        // begin https request
        var request = https.request(innerOptions, function(response) {
            var respBody = '';

            response.on('data', function(chunk) {
                respBody += chunk;
            });

            response.on('end', function() {
                var parentOcidArr = innerOptions.path.split('/');

                try {
                    respBody = JSON.parse(respBody);
                } catch (e) {
                    return callback({code:'Invalid Response'});
                }

                var parentOcidName;
                var parentOcidVal;
                if (parentOcidArr.length > 3 &&
                    parentOcidArr.length % 2 == 1) {
                    parentOcidName = parentOcidArr[parentOcidArr.length-3];
                    parentOcidVal = parentOcidArr[parentOcidArr.length-2];

                    if (respBody.length) {
                        respBody.forEach(resp => {
                            resp[parentOcidName] = parentOcidVal;
                        });
                    } else {
                        respBody[parentOcidName] = parentOcidVal;
                    }
                } else if (parentOcidArr.length > 3 &&
                    parentOcidArr.length % 2 == 0) {
                    parentOcidName = parentOcidArr[parentOcidArr.length-2];
                    parentOcidVal = parentOcidArr[parentOcidArr.length-1];

                    if (respBody.length) {
                        respBody.forEach(resp => {
                            resp[parentOcidName] = parentOcidVal;
                        });
                    } else {
                        respBody[parentOcidName] = parentOcidVal;
                    }
                }
                if (respBody.length) {
                    respBodyArr = respBodyArr.concat(respBody);
                }
                if (this.headers && this.headers['opc-next-page']) {
                    innerOptions.path = originalPath + '&page=' + this.headers['opc-next-page'];
                    makeCall(innerOptions);
                } else if (respBodyArr.length) {
                    callback(respBodyArr);
                } else {
                    callback(respBody);
                }

            });
        });

        // Create signature
        signature.sign(request, {
            key: OracleConfig.privateKey,
            keyId: [OracleConfig.tenancyId, OracleConfig.userId, OracleConfig.keyFingerprint].join('/'),
            headers: ['host', 'date', '(request-target)']
        });

        var oldAuthHead = request.getHeader('Authorization');
        var newAuthHead = oldAuthHead.replace('Signature ', 'Signature version="1",');
        request.setHeader('Authorization', newAuthHead);

        var requestToWrite = (body === undefined ? '': body);
        request.write(requestToWrite);
        request.end();
    };
    makeCall(newOptions);
}

var buildHeaders = function(allowedHeaders, options) {
    var headers = {
        'content-type': 'application/json',
        'user-agent': 'Mozilla/5.0'
    };

    for (var h in allowedHeaders) {
        var header = allowedHeaders[h].toLowerCase();
        if (options[header]) headers[header] = options[header];
    }
    return headers;
};

var buildQueryString = function(allowedStrings, options) {
    var queryString = '';
    for (var s in allowedStrings) {
        var qs = allowedStrings[s];
        if (options[qs]) queryString += (queryString == '' ? '?' : '&') + qs + '=' + encodeURIComponent(options[qs]);
    }
    return queryString;
};

module.exports = {
    call: call,
    buildHeaders: buildHeaders,
    buildQueryString: buildQueryString
};
