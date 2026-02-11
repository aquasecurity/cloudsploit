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
                    callObj.urlToCall = callObj.url;
                    for (var property in callObj.properties) {
                        callObj.urlToCall = callObj.urlToCall.replace(`{${callObj.properties[property]}}`, !callObj.subObj ? record[callObj.properties[property]] : record[callObj.subObj][callObj.properties[property]]);
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
        let collectionItems =  collection[service][callKey][region];
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
                if (callObj.filterObjKey && records.length === 1) records = records[0];

                if (records && typeof records === 'object' && !Array.isArray(records) && callObj.filterObjKey) {
                    let callObjData = [];
                    Object.keys(records).map(key => {
                        if (records[key] && records[key][callObj.filterObjKey]) {
                            if (Array.isArray(records[key][callObj.filterObjKey])) {
                                let recordsToPush = records[key][callObj.filterObjKey];
                                recordsToPush = recordsToPush.map(obj => {
                                    obj.location = key;
                                    return obj;

                                });
                                callObjData.push(...recordsToPush);
                            }
                        }
                    });
                    records =  callObjData;
                }
                if (callObj.subObj) records = records.filter(record => !!record[callObj.subObj]);
                async.eachLimit(records, callObj.maxLimit ? 35 : 10, function(record, recordCb) {
                    callObj.urlToCall = callObj.url;
                    for (var property in callObj.properties) {
                        let data = !callObj.subObj ? record[callObj.properties[property]] :  record[callObj.subObj][callObj.properties[property]];
                        if (callObj.encodeProperty){
                            data = encodeURIComponent(data);
                        }
                        callObj.urlToCall = callObj.urlToCall.replace(`{${callObj.properties[property]}}`, data);
                    }
                    if (!callObj.maxLimit || (callObj.maxLimit && collectionItems.data && collectionItems.data.length < callObj.maxLimit)) {
                        execute(LocalGoogleConfig, collection, service, callObj, callKey, region, recordCb, client, options, myEngine, true, record);
                    } else {
                        recordCb();
                    }
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
                    callObj.urlToCall = callObj.url;
                    for (var property in callObj.properties) {
                        callObj.urlToCall = callObj.urlToCall.replace(`{${callObj.properties[property]}}`, !callObj.subObj ? record[callObj.properties[property]] :  record[callObj.subObj][callObj.properties[property]]);
                    }
                    if (!callObj.maxLimit || (callObj.maxLimit && collectionItems.data && collectionItems.data.length < callObj.maxLimit)) {
                        execute(LocalGoogleConfig, collection, service, callObj, callKey, region, recordCb, client, options);
                    }  else {
                        recordCb();
                    }
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
            resultItems = setData(collectionItems, data.data.items, postCall, parent, {'service': service, 'callKey': callKey, maxLimit: callObj.maxLimit});
        } else if (callObj.dataKey && data.data[callObj.dataKey]) {
            resultItems = setData(collectionItems, data.data[callObj.dataKey], postCall, parent, {'service': service, 'callKey': callKey, maxLimit: callObj.maxLimit});
        } else if (data.data.clusters && ['kubernetes', 'dataproc'].includes(service)) {
            resultItems = setData(collectionItems, data.data['clusters'], postCall, parent, {'service': service, 'callKey': callKey, maxLimit: callObj.maxLimit});
        } else if (callObj.dataKey && data.data && data.data.length && callObj.isDataArray) {
            resultItems = setData(collectionItems, data.data[0][callObj.dataKey], postCall, parent, {'service': service, 'callKey': callKey, maxLimit: callObj.maxLimit});
        } else if (callObj.dataFilterKey && data.data[callObj.dataFilterKey]) {
            resultItems = setData(collectionItems, data.data[callObj.dataFilterKey], postCall, parent, {'service': service, 'callKey': callKey, maxLimit: callObj.maxLimit});
        } else if (data.data[service]) {
            resultItems = setData(collectionItems, data.data[service], postCall, parent, {'service': service, 'callKey': callKey, maxLimit: callObj.maxLimit});
        } else if (!myEngine && data.data.accounts) {
            resultItems = setData(collectionItems, data.data.accounts, postCall, parent, {'service': service, 'callKey': callKey, maxLimit: callObj.maxLimit});
        } else if (!myEngine && data.data.keys) {
            resultItems = setData(collectionItems, data.data.keys, postCall, parent, {'service': service, 'callKey': callKey, maxLimit: callObj.maxLimit});
        } else if (callObj.ignoreMiscData) {
            set = false;
            myEngine ? collection[service][myEngine][callKey][region].data = [] : collection[service][callKey][region].data = [];
        } else if (!myEngine && data.data) {
            resultItems = setData(collection[service][callKey][region], data.data, postCall, parent, {'service': service, 'callKey': callKey, maxLimit: callObj.maxLimit});
        } else {
            set = false;
            myEngine ? collection[service][myEngine][callKey][region].data = [] : collection[service][callKey][region].data = [];
        }
        if (set) {
            if (myEngine) collection[service][myEngine][callKey][region] = resultItems;
            else collection[service][callKey][region] = resultItems;
        }
        if (data.data && callObj.pagination && data.data.nextPageToken && (!callObj.maxLimit
            || (callObj.maxLimit && collectionItems.data && collectionItems.data.length < callObj.maxLimit))) {
            makeApiCall(client, url, executorCb, data.data.nextPageToken, { pagination: callObj.pagination, paginationKey: callObj.paginationKey, reqParams: callObj.reqParams });
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
        if (region === 'global' && callObj.globalURL) {
            url = callObj.globalURL;
        }
        url = url.replace('{projectId}', LocalGoogleConfig.project);
        if (callObj.location && callObj.location == 'zone') {
            url = url.replace('{locationId}', callObj.params.zone);
        } else if (callObj.location && callObj.location == 'region') {
            url = url.replace(/{locationId}/g, callObj.params.region);
        }
        makeApiCall(client, url, executorCb, null, {method: callObj.method, isPostCall, parentRecord, pagination: callObj.pagination, paginationKey: callObj.paginationKey, reqParams: callObj.reqParams, dataKey: callObj.dataKey, body: callObj.body});
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

var isQuotaError = function(err) {
    if (!err) return false;
    
    // Check status code (429 is used for both rate limits and quota limits)
    let statusCode = err.code || (err.response && err.response.status) || (err.response && err.response.statusCode);
    
    // Check for RESOURCE_EXHAUSTED status code or quota-related error messages
    if (statusCode === 429 || statusCode === 'RESOURCE_EXHAUSTED' || err.code === 'RESOURCE_EXHAUSTED') {
        // Check error message for quota-related keywords
        let errorMessage = '';
        if (err.message) {
            errorMessage = err.message.toLowerCase();
        } else if (err.response && err.response.data && err.response.data.error) {
            if (typeof err.response.data.error === 'string') {
                errorMessage = err.response.data.error.toLowerCase();
            } else if (err.response.data.error.message) {
                errorMessage = err.response.data.error.message.toLowerCase();
            } else if (err.response.data.error.status) {
                errorMessage = err.response.data.error.status.toLowerCase();
            }
        }
        
        // Check for quota-related keywords (quota limit errors typically mention "quota", "exceeded limit", or "resource_exhausted")
        if (errorMessage.indexOf('quota') > -1 || 
            errorMessage.indexOf('resource_exhausted') > -1 ||
            errorMessage.indexOf('quota limit') > -1 ||
            errorMessage.indexOf('exceeded limit') > -1) {
            return true;
        }
        
        // Also check if status is RESOURCE_EXHAUSTED in response data
        if (err.response && err.response.data && err.response.data.error && 
            err.response.data.error.status === 'RESOURCE_EXHAUSTED') {
            return true;
        }
    }
    
    return false;
};

function makeApiCall(client, originalUrl, callCb, nextToken, config) {
    let retries = [];
    var apiRetryAttempts = 3;
    var apiRetryBackoff = 500;
    var apiRetryCap = 1000;
    var quotaRetryDelay = 60000; // 60 seconds (1 minute) for quota limit errors

    let url = originalUrl;
    let queryParams = '';
    if (config && config.pagination) {
        queryParams = `${nextToken ? `?pageToken=${nextToken}` : ''}`;
    }
    if (config && config.reqParams) {
        queryParams = queryParams ? `${queryParams}&${config.reqParams}` : `?${config.reqParams}`;
    }
    url = `${originalUrl}${queryParams}`;
    
    // Track the last error to determine retry strategy
    let lastError = null;
    
    async.retry({
        times: apiRetryAttempts,
        interval: function(retryCount){
            // Check if last error was a quota error - apply 1 minute delay for all quota errors
            if (lastError && isQuotaError(lastError)) {
                console.log(`[Quota Limit] Detected quota limit error. Retrying after ${quotaRetryDelay/1000} seconds...`);
                retries.push({seconds: quotaRetryDelay/1000, type: 'quota_limit'});
                return quotaRetryDelay;
            }
            
            // Default exponential backoff for rate limit errors
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
            lastError = err;
            // Retry on rate errors or quota errors (for all API calls)
            return isRateError(err) || isQuotaError(err);
        }
    }, function(cb) {

        let request = {
            url,
            method: config.method ? config.method : 'GET'
        };

        if (config.body) request.body = JSON.stringify(config.body);

        client.request(request, function(err, res) {
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
    if (!serviceInfo.maxLimit || !collection.data || (serviceInfo.maxLimit && collection.data && collection.data.length < serviceInfo.maxLimit)) {
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
                collection.data = dataToAdd;
            }
        } else if (dataToAdd.constructor.name === 'Object' && Object.keys(dataToAdd).length) {
            if (Array.isArray(collection.data)) {
                collection.data.push(dataToAdd);
            } else {
                collection.data = [dataToAdd];
            }
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
    run: run,
    remediateOrgPolicy: remediateOrgPolicy,
    PROTECTION_LEVELS: ['unspecified', 'default', 'cloudcmek', 'cloudhsm', 'external'],
};

for (var s in shared) helpers[s] = shared[s];
for (var f in functions) helpers[f] = functions[f];

module.exports = helpers;
