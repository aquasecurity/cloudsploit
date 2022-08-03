var shared        = require(__dirname + '/../shared.js');
var functions     = require('./functions.js');
var regRegions    = require('./regions.js');

const {JWT}       = require('google-auth-library');

var async         = require('async');

var regions = function() {
    return regRegions;
};

var authenticate = async function(GoogleConfig) {
    const client = new JWT({
        email: GoogleConfig.client_email,
        key: GoogleConfig.private_key,
        scopes: ['https://www.googleapis.com/auth/cloud-platform'],
    });   
    return client;
};

var processCall = function(GoogleConfig, collection, settings, regions, call, service, client, serviceCb) {
    // Loop through each of the service's functions
    if (call.manyApi) {
        async.eachOfLimit(call, 5, function(callInt, item, itemsCb) {
            var myEngine = item;
            async.eachOfLimit(callInt, 5, function(callObj, callKey, callCb) {
                if (settings.api_calls && settings.api_calls.indexOf(service + ':' + myEngine + ':' + callKey) === -1) return callCb();
                if (!collection[service]) collection[service] = {};
                if (!collection[service][myEngine]) collection[service][myEngine] = {};
                if (!collection[service][myEngine][callKey]) collection[service][myEngine][callKey] = {};

                async.eachLimit(regions[service][myEngine], 5, function(region, regionCb) {
                    if (callObj.location == 'zone') {
                        async.eachLimit(regions.zones[region], 5, function(zone, zoneCb) {
                            run(GoogleConfig, collection, settings, service, callObj, callKey, zone, zoneCb, client, myEngine);
                        }, function() {
                            regionCb();
                        });
                    } else {
                        run(GoogleConfig, collection, settings, service, callObj, callKey, region, regionCb, client, myEngine);
                    }
                }, function() {
                    callCb();
                });
            }, function() {
                itemsCb();
            });
        }, function() {
            serviceCb();
        });
    } else {
        async.eachOfLimit(call, 5, function(callObj, callKey, callCb) {
            if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return callCb();
            if (!collection[service]) collection[service] = {};
            if (!collection[service][callKey]) collection[service][callKey] = {};

            async.eachLimit(regions[service], 5, function(region, regionCb) {
                if (callObj.location == 'zone') {
                    async.eachLimit(regions.zones[region], 5,function(zone, zoneCb) {
                        run(GoogleConfig, collection, settings, service, callObj, callKey, zone, zoneCb, client);
                    }, function() {
                        regionCb();
                    });
                } else {
                    run(GoogleConfig, collection, settings, service, callObj, callKey, region, regionCb, client);
                }
            }, function() {
                callCb();
            });

        }, function() {
            serviceCb();
        });
    }
};



var run = function(GoogleConfig, collection, settings, service, callObj, callKey, region, regionCb, client, myEngine) {
    
    if (settings.skip_regions &&
        settings.skip_regions.indexOf(region) > -1) return regionCb();
    var LocalGoogleConfig = JSON.parse(JSON.stringify(GoogleConfig));
    LocalGoogleConfig[callObj.location] = region;
    LocalGoogleConfig.service = service;
    LocalGoogleConfig.auth = client;
    callObj.params = JSON.parse(JSON.stringify(GoogleConfig));
    callObj.params[callObj.location] = region;
    callObj.params.service = service;
    callObj.params.auth = client;
    callObj.auth = client;

    var options = {
        params : {}
    };

    var records;    
    if (myEngine) {
        if (!collection[service][myEngine][callKey][region]) {
            collection[service][myEngine][callKey][region] = {};
            collection[service][myEngine][callKey][region].data = [];
        }
        
        if (callObj.reliesOnService) {
            if (!callObj.reliesOnService.length) {
                return regionCb();
            }
            // Ensure multiple pre-requisites are met
            for (var reliedService in callObj.reliesOnService) {
                if (callObj.reliesOnService[reliedService] && !collection[callObj.reliesOnService[reliedService]]) return regionCb();

                if (callObj.reliesOnService[reliedService] &&
                    (!collection[callObj.reliesOnService[reliedService]] ||
                    !collection[callObj.reliesOnService[reliedService]][myEngine][callObj.reliesOnCall[reliedService]] ||
                    !collection[callObj.reliesOnService[reliedService]][myEngine][callObj.reliesOnCall[reliedService]][region] ||
                    !collection[callObj.reliesOnService[reliedService]][myEngine][callObj.reliesOnCall[reliedService]][region].data ||
                    !collection[callObj.reliesOnService[reliedService]][myEngine][callObj.reliesOnCall[reliedService]][region].data.length)) return regionCb();

                records = collection[callObj.reliesOnService[reliedService]][myEngine][callObj.reliesOnCall[reliedService]][region].data;
                if (callObj.subObj) records = records.filter(record => !!record[callObj.subObj]);
                async.eachLimit(records, 10, function(record) {
                    for (var property in callObj.properties) {
                        callObj.urlToCall = callObj.url.replace(`{${callObj.properties[property]}}`, !callObj.subObj ? record[callObj.properties[property]] : record[callObj.subObj][callObj.properties[property]]);
                    }
                    execute(LocalGoogleConfig, collection, service, callObj, callKey, region, regionCb, client, options, myEngine, true, record);
                }, function() {
                    regionCb();
                });
            }
            callObj.params[callObj.properties[reliedService]] = [callObj.filterValue[reliedService]];
        } else {

            execute(LocalGoogleConfig, collection, service, callObj, callKey, region, regionCb, client, options, myEngine);
        }
    } else {

        if (!collection[service][callKey][region]) {
            collection[service][callKey][region] = {};
            collection[service][callKey][region].data = [];
        }
      
        if (callObj.reliesOnService &&
            !callObj.reliesOnSubService) {
            if (!callObj.reliesOnService.length) {
                return regionCb();
            }
            // Ensure multiple pre-requisites are met
            for (reliedService in callObj.reliesOnService) {
                if (callObj.reliesOnService[reliedService] && !collection[callObj.reliesOnService[reliedService]]) {
                    return regionCb();
                } 
                
                if (callObj.reliesOnService[reliedService] &&
                    (!collection[callObj.reliesOnService[reliedService]] ||
                    !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]] ||
                    !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]][region] ||
                    !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]][region].data ||
                    !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]][region].data.length)) return regionCb();

                records = collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]][region].data;
                if (callObj.subObj) records = records.filter(record => !!record[callObj.subObj]);
                async.eachLimit(records, 10, function(record, recordCb) {
                    for (var property in callObj.properties) {
                        callObj.urlToCall = callObj.url.replace(`{${callObj.properties[property]}}`, !callObj.subObj ? record[callObj.properties[property]] :  record[callObj.subObj][callObj.properties[property]]);
                    }
                    execute(LocalGoogleConfig, collection, service, callObj, callKey, region, recordCb, client, options, myEngine, true, record);
                }, function() {
                    regionCb();
                });
            }
        } else if (callObj.reliesOnService &&
            callObj.reliesOnSubService) {
            if (!callObj.reliesOnService.length) return regionCb();
            // Ensure multiple pre-requisites are met
            for (reliedService in callObj.reliesOnService) {
                if (callObj.reliesOnService[reliedService] && !collection[callObj.reliesOnService[reliedService]]) return regionCb();

                if (callObj.reliesOnService[reliedService] &&
                    (!collection[callObj.reliesOnService[reliedService]] ||
                        !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnSubService[reliedService]][callObj.reliesOnCall[reliedService]] ||
                        !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnSubService[reliedService]][callObj.reliesOnCall[reliedService]][region] ||
                        !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnSubService[reliedService]][callObj.reliesOnCall[reliedService]][region].data ||
                        !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnSubService[reliedService]][callObj.reliesOnCall[reliedService]][region].data.length)) return regionCb();

                records = collection[callObj.reliesOnService[reliedService]][callObj.reliesOnSubService[reliedService]][callObj.reliesOnCall[reliedService]][region].data;
                if (callObj.subObj) records = records.filter(record => !!record[callObj.subObj]);
                async.eachLimit(records, 10, function(record, recordCb) {
                    for (var property in callObj.properties) {
                        callObj.urlToCall = callObj.url.replace(`{${callObj.properties[property]}}`, !callObj.subObj ? record[callObj.properties[property]] :  record[callObj.subObj][callObj.properties[property]]);
                    }
                    execute(LocalGoogleConfig, collection, service, callObj, callKey, region, recordCb, client, options);
                }, function() {
                    regionCb();
                });
            }

        } else {
            execute(LocalGoogleConfig, collection, service, callObj, callKey, region, regionCb, client, options);
        }
    }
};
var handleErrors = function(err) {
    if (err.code) {
        if (err.code == 400) {
            return 'Invalid argument, please contact support.';
        } else if (err.code == 401) {
            if (err.response && err.response.data && err.response.data.error_description) {
                return err.response.data.error_description;
            } else {
                return 'Unauthenticated request, please contact support.';
            }
        } else if (err.code == 403) {
            if (err.response) {
                if (err.config) delete err.config;
                if (err.response && err.response.config) delete err.response.config;
                if (err.response && err.response.headers) delete err.response.headers;
                return err;
            } else {
                return 'Permission denied, please check the permissions on the service account.';
            }
        } else if (err.code == 404) {
            if (err.response) {
                if (err.config) delete err.config;
                if (err.response && err.response.config) delete err.response.config;
                if (err.response && err.response.headers) delete err.response.headers;
                return err;
            } else {
                return 'Resource not found.';
            }
        } else if (err.code == 429) {
            return 'Rate limit exceeded.';
        } else if (err.code == 500) {
            if (err.response && err.response.data && err.response.data.error_description) {
                return err.response.data.error_description;
            } else {
                return '500 Error from Google';
            }
        } else if (err.code == 503) {
            if (err.response && err.response.data && err.response.data.error_description) {
                return err.response.data.error_description;
            } else {
                return '503 Error from Google';
            }
        } else if (err.code === 'ERR_OSSL_PEM_NO_START_LINE') {
            return 'Invalid Certificate';
        } else {
            console.log(`[ERROR] Unhandled error from Google API: Error: ${JSON.stringify(err)}`);
            return 'Unknown error response from Google';
        }
    } else {
        console.log(`[ERROR] Unhandled error from Google API: Error: ${JSON.stringify(err)}`);
        return 'Unspecified Google error, please contact support';
    }
};

var execute = async function(LocalGoogleConfig, collection, service, callObj, callKey, region, regionCb, client, options, myEngine, isPostCall = false, parentRecord = {}) {
    var executorCb = function(err, data, url, postCall, parent) {
        if (err) {
            let errMessage = handleErrors(err);
            myEngine ? collection[service][myEngine][callKey][region].err = errMessage : collection[service][callKey][region].err = errMessage;
        }
        if (!data) return regionCb();
        if ((myEngine && callObj.property && !data[callObj.property]) || (callObj.property && data.data && !data.data[callObj.property])) return regionCb();
        let collectionItems = [];
        let resultItems = [];
        collectionItems = myEngine ? collection[service][myEngine][callKey][region] : collection[service][callKey][region];
        let set = true;
        if (data.data.items) {
            resultItems = setData(collectionItems, data.data.items, postCall, parent, {'service': service, 'callKey': callKey});
        } else if (data.data[service]) {
            resultItems = setData(collectionItems, data.data[service], postCall, parent, {'service': service, 'callKey': callKey});
        } else if (!myEngine && data.data.accounts) {
            resultItems = setData(collectionItems, data.data.accounts, postCall, parent, {'service': service, 'callKey': callKey});
        } else if (!myEngine && data.data.keys) {
            resultItems = setData(collectionItems, data.data.keys, postCall, parent, {'service': service, 'callKey': callKey});
        } else if (!myEngine && data.data) {
            set = false;
            if (data.data.constructor.name === 'Array') {
                collection[service][callKey][region].data.concat(data.data);
            } else if (Object.keys(data.data).length) {
                collection[service][callKey][region].data.push(data.data);
            } else if (!myEngine && !(collection[service][callKey][region].data.length)) {
                collection[service][callKey][region].data = [];
            }
            resultItems = setData(collection[service][callKey][region], data.data, postCall, parent, {'service': service, 'callKey': callKey});
        } else {
            set = false;
            myEngine ? collection[service][myEngine][callKey][region].data = [] : collection[service][callKey][region].data = [];
        }
        if (set) {
            if (myEngine) collection[service][myEngine][callKey][region] = resultItems;
            else collection[service][callKey][region] = resultItems;
        }
        if (data.data && data.data.nextPageToken) {
            makeApiCall(client, url, executorCb, data.data.nextPageToken, { pagination: callObj.pagination, paginationKey: callObj.paginationKey });
        } else {
            if (callObj.rateLimit) {
                setTimeout(function() {
                    regionCb();
                }, callObj.rateLimit);
            } else {
                regionCb();
            }
        }
    };
  
    if (callObj.url || callObj.urlToCall) {
        let url = callObj.urlToCall ? callObj.urlToCall : callObj.url;
        url = url.replace('{projectId}', LocalGoogleConfig.project);
        if (callObj.location && callObj.location == 'zone') {
            url = url.replace('{locationId}', callObj.params.zone);
        } else if (callObj.location && callObj.location == 'region') {
            url = url.replace('{locationId}', callObj.params.region);
        }

        makeApiCall(client, url, executorCb, null, {method: callObj.method, isPostCall, parentRecord, pagination: callObj.pagination, paginationKey: callObj.paginationKey});
    }
};

var isRateError = function(err) {
    let isError = false;
    var rateError = {message: 'rate', statusCode: 429};
    if (err && err.code && rateError.statusCode == err.code){
        isError = true;
    } else if (err && rateError && rateError.message && err.message &&
        err.message.toLowerCase().indexOf(rateError.message.toLowerCase()) > -1){
        isError = true;
    }

    return isError;
};

function makeApiCall(client, originalUrl, callCb, nextToken, config) {
    let retries = [];
    var apiRetryAttempts = 3;
    var apiRetryBackoff = 500;
    var apiRetryCap = 1000;

    let url = originalUrl;
    let queryParams = '';
    if (config && config.pagination) {
        queryParams = `${nextToken ? `?pageToken=${nextToken}` : ''}`;
    }
    url = `${originalUrl}${queryParams}`;
    async.retry({
        times: apiRetryAttempts,
        interval: function(retryCount){
            let retryExponential = 3;
            let retryLeveler = 3;
            let timestamp = parseInt(((new Date()).getTime()).toString().slice(-1));
            let retry_temp = Math.min(apiRetryCap, (apiRetryBackoff * (retryExponential + timestamp) ** retryCount));
            let retry_seconds = Math.round(retry_temp/retryLeveler + Math.random(0, retry_temp) * 5000);

            console.log(`Trying again in: ${retry_seconds/1000} seconds`);
            retries.push({seconds: Math.round(retry_seconds/1000)});
            return retry_seconds;
        },
        errorFilter: function(err) {
            return isRateError(err);
        }
    }, function(cb) {
        client.request({
            url,
            method: config.method ? config.method : 'GET'
        }, function(err, res) {
            if (err) {
                cb(err, null);
            } else if (res) {
                callCb(null, res, originalUrl, config.isPostCall, config.parentRecord);
            }
        });
    }, function(err, data){
        callCb(err, data);
    });    
}

function setData(collection, dataToAdd, postCall, parent, serviceInfo) {
    console.log(`[PLUGINCHECK] ${JSON.stringify(serviceInfo, null, 2)}`);
    if (postCall && !!parent) {
        if (dataToAdd && dataToAdd.length) {
            dataToAdd.map(item => {
                item.parent = parent;
                return item;
            });
        } else if (Object.keys(dataToAdd) && Object.keys(dataToAdd).length) {
            dataToAdd.parent = parent;
        }
    }
    if (dataToAdd.constructor.name === 'Array') {
        if (Array.isArray(collection.data)) {
            collection.data = collection.data.concat(dataToAdd);
        } else {
            collection.data = dataToAdd.push(collection.data);
        }
    } else {
        let existingData = collection.data;
        if (existingData && existingData.length) {
            collection.data = existingData.concat(dataToAdd);
        } else {
            collection.data = dataToAdd;
        }
    }
    return collection;
}

function remediateOrgPolicy(config, constraintName, policyType, policyValue, resource, remediation_file, putCall, pluginName, callback) {

    // url to update org policy
    var baseUrl = 'https://cloudresourcemanager.googleapis.com/v1/{resource}:setOrgPolicy';
    var method = 'POST';

    // create the params necessary for the remediation
    var body;
    if (policyType == 'booleanPolicy') {
        body = {
            policy: {
                constraint: constraintName,
                booleanPolicy: {
                    enforced: policyValue
                }
            }
        };
    }
    // logging
    remediation_file['pre_remediate']['actions'][pluginName][resource] = {
        constraintName: policyValue ? 'Disabled' : 'Enabled'
    };

    remediatePlugin(config, method, body, baseUrl, resource, remediation_file, putCall, pluginName, callback);
}

function remediatePlugin(config, method, body, baseUrl, resource, remediation_file, putCall, pluginName, callback) {
    makeRemediationCall(config, method, body, baseUrl, resource, function(err) {
        if (err) {
            remediation_file['remediate']['actions'][pluginName]['error'] = err;
            return callback(err, null);
        }

        let action = body;
        return callback(null, action);
    });
}

function makeRemediationCall(GoogleConfig, method, body, baseUrl, resource, callCb) {
    authenticate(GoogleConfig).then(client => {
        if (resource) {
            baseUrl = baseUrl.replace(/\{resource\}/g, resource);
        }
        client.request({
            url: baseUrl,
            method,
            data: body
        }, function(err, res) {
            if (err) {
                callCb(err);
            } else if (res && res.data) {
                callCb(null);
            }
        });
    });
}

var helpers = {
    regions: regions,
    MAX_REGIONS_AT_A_TIME: 6,
    authenticate: authenticate,
    processCall: processCall,
    remediatePlugin: remediatePlugin,
    remediateOrgPolicy: remediateOrgPolicy,
    PROTECTION_LEVELS: ['unspecified', 'default', 'cloudcmek', 'cloudhsm', 'external'],
};

for (var s in shared) helpers[s] = shared[s];
for (var f in functions) helpers[f] = functions[f];

module.exports = helpers;
