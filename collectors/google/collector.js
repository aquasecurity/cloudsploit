/*********************
 Collector - The collector will query Google APIs for the information required
 to run the CloudSploit scans. This data will be returned in the callback
 as a JSON object.

 Arguments:
 - GoogleConfig: If using an access key/secret, pass in the config object. Pass null if not.
 - settings: custom settings for the scan. Properties:
 - skip_regions: (Optional) List of regions to skip
 - api_calls: (Optional) If provided, will only query these APIs.
 - Example:
 {
     "skip_regions": ["us-east2", "eu-west1"],
     "api_calls": ["", ""]
 }
 - callback: Function to call when the collection is complete
 *********************/
var async = require('async');

var helpers     = require(__dirname + '/../../helpers/google');
var collectData = require(__dirname + '/../../helpers/shared');
var apiCalls    = require(__dirname + '/../../helpers/google/api.js');

var calls = apiCalls.calls;

var postcalls = apiCalls.postcalls;

var tertiarycalls = apiCalls.tertiarycalls;

var collect = function(GoogleConfig, settings, callback) {
    var collection = {};
   
    GoogleConfig.mRetries = 5;
    GoogleConfig.retryDelayOptions = {base: 300};

    let services = [];

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

    var regions = helpers.regions();

    if (settings.gather) {
        return callback(null, calls, postcalls);
    }

    helpers.authenticate(GoogleConfig)
        .then(client => {

            async.series([
                function(cb) {
                    async.eachOfLimit(calls, 10, function(call, service, serviceCb) {
                        if (!collection[service]) collection[service] = {};
                        helpers.processCall(GoogleConfig, collection, settings, regions, call, service, client, function() {
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
                                cb();
                            });
                        } else {
                            cb();
                        }
                    });
                },
                function(cb) {
                    async.eachOfLimit(postcalls, 10, function(postcallObj, service, postcallCb) {
                        helpers.processCall(GoogleConfig, collection, settings, regions, postcallObj, service, client, function() {
                            if (settings.identifier && postcalls[service].sendIntegration && postcalls[service].sendIntegration.enabled) {
                                if (!postcalls[service].sendIntegration.integrationReliesOn) {
                                    integrationCall(collection, settings, service, [], [postcalls], function() {
                                        postcallCb();
                                    });
                                } else {
                                    services.push(service);
                                    postcallCb();
                                }
                            } else {
                                postcallCb();
                            }
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
                                cb();
                            });
                        } else {
                            cb();
                        }
                    });
                },
                function(cb) {
                    async.eachOfLimit(tertiarycalls, 10, function(tertiaryCallObj, service, tertiaryCallCb) {
                        helpers.processCall(GoogleConfig, collection, settings, regions, tertiaryCallObj, service, client, function() {
                            if (settings.identifier && tertiarycalls[service].sendIntegration && tertiarycalls[service].sendIntegration.enabled) {
                                if (!tertiarycalls[service].sendIntegration.integrationReliesOn) {
                                    integrationCall(collection, settings, service, [], [tertiarycalls], function() {
                                        tertiaryCallCb();
                                    });
                                } else {
                                    services.push(service);
                                    tertiaryCallCb();
                                }
                            } else {
                                tertiaryCallCb();
                            }
                        });
                    }, function() {
                        if (settings.identifier) {
                            async.each(services, function(serv, callB) {
                                integrationCall(collection, settings, serv, [], [tertiarycalls], callB);
                            }, function(err) {
                                if (err) {
                                    console.log(err);
                                }
                                services = [];
                                cb();
                            });
                        } else {
                            cb();
                        }
                    });
                }
            ], function() {
                if (collection && (!collection.projects || !collection.projects.get)) {
                    collection.projects = {
                        ...collection.projects,
                        get: {
                            global: {
                                data: [
                                    {
                                        kind: 'compute#project',
                                        name: GoogleConfig.project
                                    }
                                ]
                            }
                        }
                    };
                }
                callback(null, collection);
            });
        });
};

module.exports = collect;