var shared        = require(__dirname + '/../shared.js');
var functions     = require('./functions.js');
var regRegions    = require('./regions.js');

const {google}    = require('googleapis');
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
        async.eachOfLimit(call, 10, function(callInt, item, itemsCb) {
            var myEngine = item;
            async.eachOfLimit(callInt, 10, function(callObj, callKey, callCb) {
                if (settings.api_calls && settings.api_calls.indexOf(service + ':' + myEngine + ':' + callKey) === -1) return callCb();
                if (!collection[service]) collection[service] = {};
                if (!collection[service][myEngine]) collection[service][myEngine] = {};
                if (!collection[service][myEngine][callKey]) collection[service][myEngine][callKey] = {};

                async.eachLimit(regions[service][myEngine], 10, function(region, regionCb) {
                    if (callObj.location == 'zone') {
                        async.each(regions.zones[region], function(zone, zoneCb) {
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
        async.eachOfLimit(call, 10, function(callObj, callKey, callCb) {
            if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return callCb();
            if (!collection[service]) collection[service] = {};
            if (!collection[service][callKey]) collection[service][callKey] = {};

            async.eachLimit(regions[service], 10, function(region, regionCb) {
                if (callObj.location == 'zone') {
                    async.each(regions.zones[region], function(zone, zoneCb) {
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

    if (callObj.parent && !callObj.reliesOnService) {
        if (!callObj.params) callObj.params = {};
        callObj.params.parent = addParent(GoogleConfig, region, callObj);
    }

    callObj.params = JSON.parse(JSON.stringify(GoogleConfig));
    callObj.params[callObj.location] = region;
    callObj.params.service = service;


    callObj.params.auth = client;
    callObj.auth = client;

    var options = {
        version: callObj.version,
        params : {}
    };

    var records;
    
    if (myEngine) {
        if (!collection[service][myEngine][callKey][region]) {
            collection[service][myEngine][callKey][region] = {};
            collection[service][myEngine][callKey][region].data = [];
        }
        
        if (callObj.reliesOnService) {
            if (!callObj.reliesOnService.length) return regionCb();
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
                async.eachLimit(records, 10, function(record) {
                    for (var filter in callObj.filterKey) {
                        callObj.params[callObj.filterKey[filter]] = record[callObj.filterValue[filter]];
                    }
                    execute(LocalGoogleConfig, collection, service, callObj, callKey, region, regionCb, options, myEngine);
                }, function() {
                    regionCb();
                });
            }
            callObj.params[callObj.filterKey[reliedService]] = [callObj.filterValue[reliedService]];
        } else {
            execute(LocalGoogleConfig, collection, service, callObj, callKey, region, regionCb, options, myEngine);
        }
    } else {
        if (!collection[service][callKey][region]) {
            collection[service][callKey][region] = {};
            collection[service][callKey][region].data = [];
        }
        if (callObj.parent && !callObj.reliesOnService) {
            if (!callObj.params) callObj.params = {};
            callObj.params.parent = addParent(GoogleConfig, region, callObj);
        }
        if (callObj.reliesOnService &&
            !callObj.reliesOnSubService) {
            if (!callObj.reliesOnService.length) return regionCb();
            // Ensure multiple pre-requisites are met
            for (reliedService in callObj.reliesOnService) {
                if (callObj.reliesOnService[reliedService] && !collection[callObj.reliesOnService[reliedService]]) return regionCb();

                if (callObj.reliesOnService[reliedService] &&
                    (!collection[callObj.reliesOnService[reliedService]] ||
                    !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]] ||
                    !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]][region] ||
                    !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]][region].data ||
                    !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]][region].data.length)) return regionCb();

                records = collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]][region].data;
                async.eachLimit(records, 10, function(record, recordCb) {
                    for (var filter in callObj.filterKey) {
                        callObj.params[callObj.filterKey[filter]] = record[callObj.filterValue[filter]];
                        options.version = callObj.version;
                    }
                    if (callObj.parent) {
                        callObj.params.parent = addParent(GoogleConfig, region, callObj);
                    }
                    execute(LocalGoogleConfig, collection, service, callObj, callKey, region, recordCb, options);
                }, function() {
                    regionCb();
                });
            }
            callObj.params[callObj.filterKey[reliedService]] = [callObj.filterValue[reliedService]];
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
                async.eachLimit(records, 10, function(record, recordCb) {
                    for (var filter in callObj.filterKey) {
                        callObj.params[callObj.filterKey[filter]] = record[callObj.filterValue[filter]];
                        options.version = callObj.version;
                    }
                    execute(LocalGoogleConfig, collection, service, callObj, callKey, region, recordCb, options);
                }, function() {
                    regionCb();
                });
            }

        } else {
            execute(LocalGoogleConfig, collection, service, callObj, callKey, region, regionCb, options);
        }
    }
};

var addParent = function(GoogleConfig, region, callObj) {
    if (callObj.location && callObj.location == 'global') {
        return `projects/${GoogleConfig.project}/locations/-`;
    } else if (callObj.location && callObj.location == 'region') {
        return `projects/${GoogleConfig.project}/locations/${region}`;
    } else if (callObj.serviceAccount) {
        return `projects/${GoogleConfig.project}/serviceAccounts/${callObj.params.id}`;
    } else {
        return `projects/${GoogleConfig.project}`;
    }
};

var execute = function(LocalGoogleConfig, collection, service, callObj, callKey, region, regionCb, options, myEngine) {
    var executor = new google[callObj.api](options);
    var executorCb = function(err, data) {
        if (myEngine) {
            if (err) {
                collection[service][myEngine][callKey][region].err = err;
            }

            if (!data) return regionCb();
            if (callObj.property && !data[callObj.property]) return regionCb();
            if (callObj.secondProperty && !data[callObj.secondProperty]) return regionCb();

            if (callObj.secondProperty) {
                collection[service][myEngine][callKey][region].data = data[callObj.property][callObj.secondProperty];
            } else {
                if (data.data.items) {
                    collection[service][myEngine][callKey][region].data = data.data.items;
                } else if (data.data[service]) {
                    collection[service][myEngine][callKey][region].data = data.data[service];
                } else {
                    collection[service][myEngine][callKey][region].data = [];
                }
            }

            if (callObj.rateLimit) {
                setTimeout(function() {
                    regionCb();
                }, callObj.rateLimit);
            } else {
                regionCb();
            }
        } else {
            if (err) {
                collection[service][callKey][region].err = err;
            }

            if (!data) return regionCb();
            if (callObj.property && !data[callObj.property]) return regionCb();
            if (callObj.secondProperty && !data[callObj.secondProperty]) return regionCb();

            if (callObj.secondProperty) {
                collection[service][callKey][region].data = data[callObj.property][callObj.secondProperty];
            } else {
                if (data.data.items) {
                    if (data.data.items.constructor.name === 'Array') {
                        collection[service][callKey][region].data = collection[service][callKey][region].data.concat(data.data.items);
                    } else {
                        collection[service][callKey][region].data = data.data.items;
                    }
                } else if (data.data[service]) {
                    if (data.data[service].constructor.name === 'Array') {
                        collection[service][callKey][region].data = collection[service][callKey][region].data.concat(data.data[service]);
                    } else {
                        collection[service][callKey][region].data.push(data.data[service]);
                    }
                }
                else if (data.data.accounts) {
                    if (data.data.accounts.constructor.name === 'Array') {
                        collection[service][callKey][region].data = collection[service][callKey][region].data.concat(data.data.accounts);
                    } else {
                        collection[service][callKey][region].data.push(data.data.accounts);
                    }
                } else if (data.data) {
                    if (data.data.constructor.name === 'Array') {
                        collection[service][callKey][region].data.concat(data.data);
                    } else if (Object.keys(data.data).length){
                        collection[service][callKey][region].data.push(data.data);
                    } else {
                        collection[service][callKey][region].data = [];
                    }
                } else {
                    collection[service][callKey][region].data = [];
                }
            }

            if (callObj.rateLimit) {
                setTimeout(function() {
                    regionCb();
                }, callObj.rateLimit);
            } else {
                regionCb();
            }
        }
    };
    var parentParams;
    if (callObj.nested && callObj.parent) {
        parentParams = {auth: callObj.params.auth, parent: callObj.params.parent};
        executor['projects']['locations'][service][callKey](parentParams, LocalGoogleConfig, executorCb);
    } else if(callObj.nested) {
        parentParams = {auth: callObj.params.auth, parent: callObj.params.parent};
        executor['projects']['locations']['keyRings'][service][callKey](parentParams, LocalGoogleConfig, executorCb);
    } else if (callObj.resource) {
        parentParams = {auth: callObj.auth, resource_: LocalGoogleConfig.project};
        executor[service][callKey](parentParams, LocalGoogleConfig, executorCb);
    } else if (callObj.serviceAccount) {
        parentParams = {auth: callObj.params.auth, name: callObj.params.parent};
        executor['projects']['serviceAccounts'][service][callKey](parentParams, LocalGoogleConfig, executorCb);
    } else if (callObj.parent && callObj.parent === 'name') {
        parentParams = {auth: callObj.params.auth, name: callObj.params.parent};
        executor['projects'][service][callKey](parentParams, LocalGoogleConfig, executorCb);
    } else if (callObj.parent) {
        parentParams = {auth: callObj.params.auth, parent: callObj.params.parent};
        executor['projects'][service][callKey](parentParams, LocalGoogleConfig, executorCb);
    } else if (callObj.params) {
        executor[service][callKey](callObj.params, LocalGoogleConfig, executorCb);
    } else {
        executor[service][callKey](LocalGoogleConfig, executorCb);
    }    
};

var helpers = {
    regions: regions,
    MAX_REGIONS_AT_A_TIME: 6,
    authenticate: authenticate,
    processCall: processCall
};

for (var s in shared) helpers[s] = shared[s];
for (var f in functions) helpers[f] = functions[f];

module.exports = helpers;
