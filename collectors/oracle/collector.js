/*********************
 Collector - The collector will query Oracle's APIs for the information required
 to run the CloudSploit scans. This data will be returned in the callback
 as a JSON object.

 Arguments:
 - OracleConfig: Required Authentication parameters for Oracle's REST API.
 - settings: custom settings for the scan. Properties:
 - skip_regions: (Optional) List of regions to skip
 - api_calls: (Optional) If provided, will only query these APIs.
 - Example:
 {
     'skip_regions': [', '],
     'api_calls': ['EC2:describeInstances', 'S3:listBuckets']
 }
 - callback: Function to call when the collection is complete
 *********************/

var async = require('async');

var helpers = require(__dirname + '/../../helpers/oracle');
var collectData = require(__dirname + '/../../helpers/shared');
var apiCalls    = require(__dirname + '/../../helpers/oracle/api.js');

var calls = apiCalls.calls;

var postcalls = apiCalls.postcalls;

var finalcalls = apiCalls.finalcalls;

var regionSubscriptionService;

var globalServices = [
    'core'
];

var processCall = function(OracleConfig, collection, settings, regions, call, service, serviceCb) {
    // Loop through each of the service's functions
    async.eachOfLimit(call, 10, function(callObj, callKey, callCb) {
        if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return callCb();
        if (!collection[service][callKey]) collection[service][callKey] = {};

        async.eachLimit(regions[service], helpers.MAX_REGIONS_AT_A_TIME, function(region, regionCb) {
            if (region === 'default') {
                region = OracleConfig.region ? OracleConfig.region : 'us-ashburn-1';
            }

            if (settings.skip_regions &&
                settings.skip_regions.indexOf(region) > -1 &&
                globalServices.indexOf(service) === -1) return regionCb();

            // Ignore regions we are not subscribed to
            if (collection[regionSubscriptionService.name] &&
                collection[regionSubscriptionService.name][regionSubscriptionService.call] &&
                collection[regionSubscriptionService.name][regionSubscriptionService.call][regionSubscriptionService.region] &&
                collection[regionSubscriptionService.name][regionSubscriptionService.call][regionSubscriptionService.region].data &&
                collection[regionSubscriptionService.name][regionSubscriptionService.call][regionSubscriptionService.region].data.filter(r => r.regionName == region) &&
                collection[regionSubscriptionService.name][regionSubscriptionService.call][regionSubscriptionService.region].data.filter(r => r.regionName == region).length == 0) {
                return regionCb();
            }
            if (!collection[service][callKey][region]) collection[service][callKey][region] = {};

            if (callObj.reliesOnService) {
                if (!callObj.reliesOnService.length) return regionCb();
                // Ensure multiple pre-requisites are met
                for (var reliedService in callObj.reliesOnService) {
                    if (callObj.reliesOnService[reliedService] && !collection[callObj.reliesOnService[reliedService]]) return regionCb();

                    if (callObj.reliesOnService[reliedService] &&
                        (!collection[callObj.reliesOnService[reliedService]] ||
                        !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]] ||
                        !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]][region] ||
                        !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]][region].data)) return regionCb();
                }
            }

            var LocalOracleConfig = JSON.parse(JSON.stringify(OracleConfig));
            LocalOracleConfig.region = region;
            LocalOracleConfig.service = service;


            var executor = new helpers.OracleExecutor(LocalOracleConfig);
            executor.run(collection, service, callObj, callKey, function(err, data) {
                if (err && err.length) {
                    collection[service][callKey][region].err = err;
                }

                if (!data) return regionCb();
                collection[service][callKey][region].data = data;

                if (callObj.rateLimit) {
                    setTimeout(function() {
                        regionCb();
                    }, callObj.rateLimit);
                } else {
                    regionCb();
                }
            });
        }, function() {
            callCb();
        });
    }, function() {
        serviceCb();
    });
};

let integrationCall = function(collection, settings, service, calls, postcalls, cback) {
    let collect = JSON.parse(JSON.stringify(collection));
    collect = Object.keys(collect).reduce((accumulator, key) => {
        accumulator[key.toLowerCase()] = collect[key];
        return accumulator;
    }, {});

    settings.previousCollection = Object.keys(settings.previousCollection).reduce((accumulator, key) => {
        accumulator[key.toLowerCase()] = settings.previousCollection[key];
        return accumulator;
    }, {});

    if (collect[service.toLowerCase()] &&
        Object.keys(collect[service.toLowerCase()]) &&
        Object.keys(collect[service.toLowerCase()]).length &&
        collectData.callsCollected(service, collect, calls, postcalls)
    ) {
        try {
            collectData.processIntegration(service, settings, collect, calls, postcalls, false,function() {
                cback();
            });
        } catch (e) {
            console.log(`Error in storing ${service} service data: ${JSON.stringify(e)}`);
            cback();
        }
    } else {
        cback();
    }
};


var getRegionSubscription = function(OracleConfig, collection, settings, calls, service, callKey, region, serviceCb) {

    var LocalOracleConfig = JSON.parse(JSON.stringify(OracleConfig));
    LocalOracleConfig.service = service;

    if (!collection[service]) collection[service] = {};
    if (!collection[service][callKey]) collection[service][callKey] = {};
    if (!collection[service][callKey][region]) collection[service][callKey][region] = {};

    var executor = new helpers.OracleExecutor(LocalOracleConfig);
    executor.run(collection, service, calls[service][callKey], callKey, function(err, data) {
        if (err) {
            collection[service][callKey][region].err = err;
        }

        if (!data) return serviceCb();

        collection[service][callKey][region].data = data;

        serviceCb();
    });
};

// Loop through all of the top-level collectors for each service
var collect = function(OracleConfig, settings, callback) {
    var collection = {};
    OracleConfig.region = OracleConfig.region ? OracleConfig.region : 'us-ashburn-1';
    OracleConfig.maxRetries = 5;
    OracleConfig.retryDelayOptions = {base: 300};
    regionSubscriptionService = {name: 'regionSubscription', call: 'list', region: OracleConfig.region};

    if (settings.gather) {
        return callback(null, calls, postcalls, finalcalls);
    }

    var regions = helpers.regions(settings.govcloud);
    let services = [];

    getRegionSubscription(OracleConfig, collection, settings, calls, regionSubscriptionService.name, regionSubscriptionService.call, regionSubscriptionService.region, function() {
        async.eachOfLimit(calls, 10, function(call, service, serviceCb) {
            if (!collection[service]) collection[service] = {};

            processCall(OracleConfig, collection, settings, regions, call, service, function() {
                if (settings.identifier && calls[service].sendIntegration && calls[service].sendIntegration.enabled) {
                    if (!calls[service].sendIntegration.integrationReliesOn) {
                        integrationCall(collection, settings, service, calls, [], function() {
                            serviceCb();
                        });
                    } else {
                        services.push(service);
                        serviceCb();
                    }
                } else {
                    serviceCb();
                }
                // serviceCb();
            });
        }, function() {
            if (settings.identifier) {
                async.each(services, function(serv, callB) {
                    integrationCall(collection, settings, serv, calls, [], callB);
                }, function(err) {
                    if (err) {
                        console.log(err);
                    }
                    services = [];
                });
            }
            // Now loop through the follow up calls
            async.eachOfLimit(postcalls, 10, function(postCall, service, serviceCb) {
                if (!collection[service]) collection[service] = {};

                processCall(OracleConfig, collection, settings, regions, postCall, service, function() {
                    if (settings.identifier && postcalls[service].sendIntegration && postcalls[service].sendIntegration.enabled) {
                        if (!postcalls[service].sendIntegration.integrationReliesOn) {
                            integrationCall(collection, settings, service, [], [postcalls], function() {
                                serviceCb();
                            });
                        } else {
                            services.push(service);
                            serviceCb();
                        }
                    } else {
                        serviceCb();
                    }
                    // serviceCb();
                });
            }, function() {
                if (settings.identifier) {
                    async.each(services, function(serv, callB) {
                        integrationCall(collection, settings, serv, [], [postcalls], callB);
                    }, function(err) {
                        if (err) {
                            console.log(err);
                        }
                        services = [];
                    });
                }
                // Now loop through the follow up calls
                async.eachOfLimit(finalcalls, 10, function(finalCall, service, serviceCb) {
                    if (!collection[service]) collection[service] = {};

                    processCall(OracleConfig, collection, settings, regions, finalCall, service, function() {
                        if (settings.identifier && finalcalls[service].sendIntegration && finalcalls[service].sendIntegration.enabled) {
                            if (!finalcalls[service].sendIntegration.integrationReliesOn) {
                                integrationCall(collection, settings, service, [], [finalcalls], function() {
                                    serviceCb();
                                });
                            } else {
                                services.push(service);
                                serviceCb();
                            }
                        } else {
                            serviceCb();
                        }
                        // serviceCb();
                    });
                }, function() {
                    if (settings.identifier) {
                        async.each(services, function(serv, callB) {
                            integrationCall(collection, settings, serv, [], [finalcalls], callB);
                        }, function(err) {
                            if (err) {
                                console.log(err);
                            }
                            services = [];
                        });
                    }
                    //console.log(JSON.stringify(collection, null, 2));
                    callback(null, collection);
                });
            }, function() {
                //console.log(JSON.stringify(collection, null, 2));
                callback(null, collection);
            });
        }, function() {
            //console.log(JSON.stringify(collection, null, 2));
            callback(null, collection);
        });
    });
};

module.exports = collect;