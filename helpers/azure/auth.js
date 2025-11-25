var locations = require(__dirname + '/locations.js');
var axios = require('axios');
var locations_gov = require(__dirname + '/locations_gov.js');

var dontReplace = {
    'type': {
        'roleDefinitions': 'roleType'
    }
};

// Recursive function that converts API response containing "properties"
// into single unified response with properties at top-level.
// This matches the format of the now-replaced SDK.
function reduceProperties(service, collection) {
    if (Array.isArray(collection)) {
        collection.forEach(function(col) {
            reduceProperties(service, col);
        });
    } else if (typeof collection == 'object') {
        if (collection.properties && typeof collection.properties == 'object') {
            for (var p in collection.properties) {
                if (dontReplace[p] && dontReplace[p][service]) {
                    collection[dontReplace[p][service]] = collection.properties[p];
                } else {
                    collection[p] = collection.properties[p];
                }
            }
            delete collection.properties;
        }
    }
}

module.exports = {
    login: function(azureConfig, callback) {
        if (!azureConfig.ApplicationID) return callback('No ApplicationID provided');
        if (!azureConfig.KeyValue) return callback('No KeyValue provided');
        if (!azureConfig.DirectoryID) return callback('No DirectoryID provided');
        if (!azureConfig.SubscriptionID) return callback('No SubscriptionID provided');
        var { ClientSecretCredential } = require('@azure/identity');

        function getToken(credential, scopes, cb) {
            credential.getToken(scopes)
                .then(response => {
                    cb(null, response.token);
                })
                .catch(error => {
                    cb(error);
                });
        }

        const credential = new ClientSecretCredential(
            azureConfig.DirectoryID,
            azureConfig.ApplicationID,
            azureConfig.KeyValue
        );

        if (azureConfig.Govcloud) {
            const armScope = 'https://management.usgovcloudapi.net/.default';
            const graphScope = 'https://graph.microsoft.us/.default';
            const vaultScope = 'https://vault.azure.us/.default';

            getToken(credential, [armScope], function(err, armToken) {
                if (err) return callback(err);
                getToken(credential, [graphScope], function(graphErr, graphToken) {
                    if (graphErr) return callback(graphErr);
                    getToken(credential, [vaultScope], function(vaultErr, vaultToken) {
                        if (vaultErr) console.log('No vault');
                        callback(null, {
                            environment: {
                                name: 'AzureUSGovernment',
                                portalUrl: 'https://portal.azure.us'
                            },
                            token: armToken,
                            graphToken: graphToken,
                            vaultToken: vaultToken
                        });
                    });
                });
            });
        } else {
            const armScope = 'https://management.azure.com/.default';
            const graphScope = 'https://graph.microsoft.com/.default';
            const vaultScope = 'https://vault.azure.net/.default';

            getToken(credential, [armScope], function(err, armToken) {
                if (err) return callback(err);
                getToken(credential, [graphScope], function(graphErr, graphToken) {
                    if (graphErr) return callback(graphErr);
                    getToken(credential, [vaultScope], function(vaultErr, vaultToken) {
                        if (vaultErr) return callback(vaultErr);
                        callback(null, {
                            environment: {
                                name: 'AzureCloud',
                                portalUrl: 'https://portal.azure.com'
                            },
                            token: armToken,
                            graphToken: graphToken,
                            vaultToken: vaultToken
                        });
                    });
                });
            });
        }
    },

    call: function(params, callback) {
        var headers = {
            'Authorization': `Bearer ${params.token}`
        };

        var requestData = null;
        if (params.body && Object.keys(params.body).length) {
            requestData = JSON.stringify(params.body);
            headers['Content-Length'] = requestData.length;
            headers['Content-Type'] = 'application/json;charset=UTF-8';
        }

        if (params.govcloud) params.url = params.url.replace('management.azure.com', 'management.usgovcloudapi.net');

        var axiosOptions = {
            method: params.method ? params.method : params.post ? 'POST' : 'GET',
            url: params.url,
            headers: headers,
            data: requestData,
            // Handle response as text first, then parse manually to match original behavior
            transformResponse: [(data) => data]
        };

        axios(axiosOptions)
            .then(function(response) {
                var body = response.data;

                if (response && [200, 202].includes(response.status) && body) {
                    try {
                        body = JSON.parse(body);
                    } catch (e) {
                        return callback(`Error parsing response from Azure API: ${e}`);
                    }
                    return callback(null, body);
                } else {
                    handleErrorResponse(body, response, callback);
                }
            })
            .catch(function(error) {
                if (error.response) {
                    // The request was made and the server responded with a status code outside 2xx
                    handleErrorResponse(error.response.data, error.response, callback);
                } else if (error.request) {
                    // The request was made but no response was received
                    if (error.code === 'ECONNRESET') {
                        console.log('[ERROR] Unhandled error from Azure API: Error: ECONNRESET');
                        return callback('Unknown error occurred while calling the Azure API: ECONNRESET');
                    }
                    console.log(`[ERROR] Unhandled error from Azure API: Error: ${error}`);
                    return callback('Unknown error occurred while calling the Azure API');
                } else {
                    // Something happened in setting up the request
                    console.log(`[ERROR] Unhandled error from Azure API: Error: ${error}`);
                    return callback('Unknown error occurred while calling the Azure API');
                }
            });

        function handleErrorResponse(body, response, callback) {
            if (body) {
                try {
                    body = JSON.parse(body);
                } catch (e) {
                    return callback(`Error parsing error response from Azure API: ${e}`);
                }

                if (typeof body == 'string') {
                    // Need to double parse it
                    try {
                        body = JSON.parse(body);
                    } catch (e) {
                        return callback(`Error parsing error response string from Azure API: ${e}`);
                    }
                }

                if (response && ((response.statusCode && response.statusCode === 429) || (response.status && response.status === 429)) &&
                    body &&
                    body.error &&
                    body.error.message &&
                    typeof body.error.message == 'string') {
                    var errorMessage = `TooManyRequests: ${body.error.message}`;
                    return callback(errorMessage, null, response);
                } else if (body &&
                    body.error &&
                    body.error.message &&
                    typeof body.error.message == 'string') {
                    return callback(body.error.message);
                } else if (body &&
                    body['odata.error'] &&
                    body['odata.error'].message &&
                    body['odata.error'].message.value &&
                    typeof body['odata.error'].message.value == 'string') {
                    if (body['odata.error'].requestId) {
                        body['odata.error'].message.value += ` RequestId: ${body['odata.error'].requestId}`;
                    }
                    return callback(body['odata.error'].message.value);
                } else if (body &&
                    body.message &&
                    typeof body.message == 'string') {
                    if (body.code && typeof body.code == 'string') {
                        body.message = (body.code + ': ' + body.message);
                    }
                    return callback(body.message);
                } else if (body &&
                    body.Message &&
                    typeof body.Message == 'string') {
                    if (body.Code && typeof body.Code == 'string') {
                        body.Message = (body.Code + ': ' + body.Message);
                    }
                    return callback(body.Message);
                }
                if (typeof body == 'string') {
                    // Need to double parse it
                    try {
                        body = JSON.parse(body);
                    } catch (e) {
                        return callback(`Error parsing error response string from Azure API: ${e}`);
                    }
                }
                if (response && ((response.statusCode && response.statusCode === 429) || (response.status && response.status === 429)) &&
                    body &&
                    body.error &&
                    body.error.message &&
                    typeof body.error.message == 'string') {
                    errorMessage = `TooManyRequests: ${body.error.message}`;
                    return callback(errorMessage, null, response);
                } else if (body &&
                    body.error &&
                    body.error.message &&
                    typeof body.error.message == 'string') {
                    return callback(body.error.message);
                } else if (body &&
                    body['odata.error'] &&
                    body['odata.error'].message &&
                    body['odata.error'].message.value &&
                    typeof body['odata.error'].message.value == 'string') {
                    if (body['odata.error'].requestId) {
                        body['odata.error'].message.value += ` RequestId: ${body['odata.error'].requestId}`;
                    }
                    return callback(body['odata.error'].message.value);
                } else if (body &&
                    body.message &&
                    typeof body.message == 'string') {
                    if (body.code && typeof body.code == 'string') {
                        body.message = (body.code + ': ' + body.message);
                    }
                    return callback(body.message);
                } else if (body &&
                    body.Message &&
                    typeof body.Message == 'string') {
                    if (body.Code && typeof body.Code == 'string') {
                        body.Message = (body.Code + ': ' + body.Message);
                    }
                    return callback(body.Message);
                }

                console.log(`[ERROR] Unhandled error from Azure API: Body: ${JSON.stringify(body)}`);
            }

            console.log('[ERROR] Unhandled error from Azure API');
            return callback('Unknown error occurred while calling the Azure API');
        }
    },

    addLocations: function(obj, service, collection, err, data, skip_locations) {
        if (!service || !locations[service]) return;
        locations[service].forEach(function(location) {
            if (skip_locations.includes(location)) return;
            collection[location.toLowerCase()] = {};
            if (err) {
                collection[location.toLowerCase()].err = err;
            } else if (data) {
                if (data.value && Array.isArray(data.value)) {
                    collection[location.toLowerCase()].data = data.value.filter(function(dv) {
                        if (dv.location &&
                            dv.location.toLowerCase().replace(/ /g, '') == location.toLowerCase()) {
                            return true;
                        } else if (location.toLowerCase() == 'global' && (!dv.location || obj.ignoreLocation)) {
                            return true;
                        }
                        return false;
                    });
                    reduceProperties(service, collection[location.toLowerCase()].data);
                }
            }
        });
    },

    addGovLocations: function(obj, service, collection, err, data, skip_locations) {
        if (!service || !locations_gov[service]) return;
        locations_gov[service].forEach(function(location) {
            if (skip_locations.includes(location)) return;
            collection[location.toLowerCase()] = {};
            if (err) {
                collection[location.toLowerCase()].err = err;
            } else if (data) {
                if (data.value && Array.isArray(data.value)) {
                    collection[location.toLowerCase()].data = data.value.filter(function(dv) {
                        if (dv.location &&
                            dv.location.toLowerCase().replace(/ /g, '') == location.toLowerCase()) {
                            return true;
                        } else if (location.toLowerCase() == 'global' && (!dv.location || obj.ignoreLocation)) {
                            return true;
                        }
                        return false;
                    });
                    reduceProperties(service, collection[location.toLowerCase()].data);
                }
            }
        });
    },

    reduceProperties: reduceProperties
};