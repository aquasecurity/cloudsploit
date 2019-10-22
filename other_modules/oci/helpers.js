var https = require('https');
var signature = require('http-signature');

function call(OracleConfig, options, callback) {
    var body = JSON.stringify(options.body);
    delete options.body;

    // begin https request
    var request = https.request(options, function(response) {
        var respBody = '';

        response.on('data', function(chunk) { 
            respBody += chunk;
        });

        response.on('end', function() {
            var parentOcidArr = options.path.split('/');

            try {
                respBody = JSON.parse(respBody);
            } catch (e) {
                return callback({code:'Invalid Response'});
            }

            if (parentOcidArr.length > 3 &&
                parentOcidArr.length % 2 == 1) {
                var parentOcidName = parentOcidArr[parentOcidArr.length-3];
                var parentOcidVal = parentOcidArr[parentOcidArr.length-2];

                if (respBody.length) {
                    respBody.forEach(resp => {
                        resp[parentOcidName] = parentOcidVal
                    });
                } else {
                    respBody[parentOcidName] = parentOcidVal
                }
            } else if (parentOcidArr.length > 3 &&
                parentOcidArr.length % 2 == 0) {
                var parentOcidName = parentOcidArr[parentOcidArr.length-2];
                var parentOcidVal = parentOcidArr[parentOcidArr.length-1];

                if (respBody.length) {
                    respBody.forEach(resp => {
                        resp[parentOcidName] = parentOcidVal
                    });
                } else {
                    respBody[parentOcidName] = parentOcidVal
                }
            }
            callback(respBody);
        });
    });

    // Create signature
    signature.sign(request, {
        key: OracleConfig.privateKey,
        keyId: [OracleConfig.tenancyId, OracleConfig.userId, OracleConfig.keyFingerprint].join('/'),
        headers: ["host", "date", "(request-target)"]
    });

    var oldAuthHead = request.getHeader("Authorization");
    var newAuthHead = oldAuthHead.replace("Signature ", "Signature version=\"1\",");
    request.setHeader("Authorization", newAuthHead);

    var requestToWrite = (body === undefined ? '': body);
    request.write(requestToWrite);
    request.end();
}

var buildHeaders = function(allowedHeaders, options) {
    var headers = {
        'content-type': 'application/json',
        'user-agent': 'Mozilla/5.0'
    };

    for (h in allowedHeaders) {
        var header = allowedHeaders[h].toLowerCase();
        if (options[header]) headers[header] = options[header];
    }
    return headers;
};

var buildQueryString = function (allowedStrings, options) {
    var queryString = '';
    for (s in allowedStrings) {
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
