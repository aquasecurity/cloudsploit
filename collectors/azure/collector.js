/*********************
 Collector - The collector will query Azure APIs for the information required
 to run the CloudSploit scans. This data will be returned in the callback
 as a JSON object.

 Arguments:
 - AzureConfig: If using an access key/secret, pass in the config object. Pass null if not.
 - settings: custom settings for the scan. Properties:
 - skip_locations: (Optional) List of locations to skip
 - api_calls: (Optional) If provided, will only query these APIs.
 - Example:
 {
     "skip_locations": ["eastus", "westus"],
     "api_calls": ["storageAccounts:list", "resourceGroups:list"]
 }
 - callback: Function to call when the collection is complete
 *********************/

var async = require('async');
var collectors = require(__dirname + '/index.js');
var collectData = require(__dirname + '/../../helpers/shared.js');
var apiCalls = require(__dirname + '/../../helpers/azure/api.js');

// Standard calls that contain top-level operations
var calls = apiCalls.calls;

var postcalls = apiCalls.postcalls;

var tertiarycalls = apiCalls.tertiarycalls;

var specialcalls = apiCalls.specialcalls;

function parseCollection(path, obj) {
    if (typeof path == 'string') path = path.split('.');
    if (path.length) {
        var localPath = path.shift();
        if (obj[localPath]) {
            return parseCollection(path, obj[localPath]);
        } else {
            return false;
        }
    } else {
        return obj;
    }
}

let collect = function(AzureConfig, settings, callback) {
    // Used to gather info only
    if (settings.gather) {
        return callback(null, calls, postcalls, tertiarycalls, specialcalls);
    }

    var helpers = require(__dirname + '/../../helpers/azure/auth.js');

    let services = [];
    let skip_locations= settings.skip_regions || [];

    // Login using the Azure config
    helpers.login(AzureConfig, function(loginErr, loginData) {
        if (loginErr) return callback(loginErr);

        var collection = {};

        let makeCall = function(localUrl, obj, cb, localData) {
            helpers.call({
                url: localUrl,
                post: obj.post,
                token: obj.graph ? loginData.graphToken : (obj.vault ? loginData.vaultToken : loginData.token),
                govcloud : AzureConfig.Govcloud
            }, function(err, data) {
                if (err) return cb(err);

                // If a new nextLink is provided, this will be updated.  There shouldn't
                // be a need to hold on to the previous value
                if (data && obj.hasListResponse && data.length) data.value = data;

                if (data && obj.getCompleteResponse) {
                    data = {value: [data]};
                }

                obj.nextUrl = null;
                if (data && data.value && Array.isArray(data.value) && data.value.length && localData && localData.value) {
                    localData.value = localData.value.concat(data.value);
                } else if (localData && localData.value && localData.value.length && (!data || !((obj.paginate && data[obj.paginate]) || data['nextLink']))) {
                    return cb(null, localData);
                }

                let resData = localData || data;
                if (data && ((obj.paginate && data[obj.paginate]) || data['nextLink']) && (!obj.limit || (obj.limit && resData && resData.value && resData.value.length < obj.limit))) {
                    obj.nextUrl = data['nextLink'] || data[obj.paginate];
                    processCall(obj, cb, localData || data);
                } else {
                    return cb(null, localData || data || []);
                }
            });
        };

        let processCall = function(obj, cb, localData) {
            let localUrl = obj.nextUrl || obj.url.replace(/\{subscriptionId\}/g, AzureConfig.SubscriptionID);
            if (obj.rateLimit) {
                setTimeout(function() {
                    console.log(`url: ${localUrl}`);
                    makeCall(localUrl, obj, cb, localData);
                }, obj.rateLimit);
            } else {
                makeCall(localUrl, obj, cb, localData);
            }
        };

        let integrationCall = function(collection, settings, service, calls, postcalls, cback) {
            let collect = JSON.parse(JSON.stringify(collection));
            collect = Object.keys(collect).reduce((accumulator, key) => {
                accumulator[key.toLowerCase()] = collect[key];
                return accumulator;
            }, {});

            if (settings.previousCollection) {
                settings.previousCollection = Object.keys(settings.previousCollection).reduce((accumulator, key) => {
                    accumulator[key.toLowerCase()] = settings.previousCollection[key];
                    return accumulator;
                }, {});
            }

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

        async.series([
            // Calls - process the simple calls
            function(cb) {
                function processTopCall(collectionObj, service, subCallObj, subCallCb) {
                    processCall(subCallObj, function(processCallErr, processCallData) {
                        if (AzureConfig.Govcloud) helpers.addGovLocations(subCallObj, service, collectionObj, processCallErr, processCallData , skip_locations);
                        else helpers.addLocations(subCallObj, service, collectionObj, processCallErr, processCallData , skip_locations);
                        subCallCb();
                    });
                }

                async.eachOfLimit(calls, 10, function(callObj, service, callCb) {
                    if (!collection[service]) collection[service] = {};
                    // Loop through sub-calls
                    async.eachOf(callObj, function(subCallObj, one, subCallCb) {
                        // Skip API calls unless required
                        if (settings &&
                            settings.api_calls &&
                            settings.api_calls.indexOf([service, one].join(':')) === -1) return subCallCb();

                        if (!collection[service][one]) collection[service][one] = {};
                        processTopCall(collection[service][one], service, subCallObj, subCallCb);
                    }, function() {
                        if (settings.identifier && calls[service].sendIntegration && calls[service].sendIntegration.enabled) {
                            if (!calls[service].sendIntegration.integrationReliesOn) {
                                integrationCall(collection, settings, service, calls, [], function() {
                                    callCb();
                                });
                            } else {
                                services.push(service);
                                callCb();
                            }
                        } else {
                            callCb();
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

            // Post Calls - secondary calls that rely on calls
            function(cb) {
                function processTopCall(collectionObj, service, subCallObj, subCallCb) {
                    // Loop through original properties
                    var regionsToLoop = parseCollection(subCallObj.reliesOnPath, collection);
                    if (regionsToLoop && Object.keys(regionsToLoop).length) {
                        // Loop through regions
                        async.eachOfLimit(regionsToLoop, 5, function(regionObj, region, regionCb) {
                            if (regionObj && regionObj.data && regionObj.data.length) {
                                if (!collectionObj[region]) collectionObj[region] = {};
                                async.eachLimit(regionObj.data, 10, function(regionData, regionDataCb) {
                                    var localReq = {
                                        url: subCallObj.url,
                                        post: subCallObj.post,
                                        token: subCallObj.token,
                                        graph: subCallObj.graph,
                                        vault: subCallObj.vault,
                                        rateLimit: subCallObj.rateLimit,
                                        limit: subCallObj.limit
                                    };
                                    // Check and replace properties
                                    if (subCallObj.properties && subCallObj.properties.length) {
                                        subCallObj.properties.forEach(function(propToReplace) {
                                            if (propToReplace.includes('.')) {
                                                regionData[propToReplace] = parseCollection(propToReplace, regionData);
                                            }
                                            if (regionData[propToReplace]) {
                                                var re = new RegExp(`{${propToReplace}}`, 'g');
                                                localReq.url = subCallObj.url.replace(re, regionData[propToReplace]);
                                            }
                                        });
                                    }

                                    // Add ID
                                    collectionObj[region][regionData.id] = {};

                                    // Call and process API
                                    processCall(localReq, function(processCallErr, processCallData) {
                                        if (processCallErr) collectionObj[region][regionData.id].err = processCallErr;
                                        if (processCallData) {
                                            if (processCallData.value) {
                                                collectionObj[region][regionData.id].data = processCallData.value;
                                            } else {
                                                collectionObj[region][regionData.id].data = processCallData;
                                            }
                                            helpers.reduceProperties(service, collectionObj[region][regionData.id].data);
                                        }
                                        regionDataCb();
                                    });
                                }, function() {
                                    regionCb();
                                });
                            } else {
                                regionCb();
                            }
                        }, function() {
                            subCallCb();
                        });
                    } else {
                        subCallCb();
                    }
                }

                async.eachOfLimit(postcalls, 10, function(callObj, service, callCb) {
                    if (!collection[service]) collection[service] = {};
                    // Loop through sub-calls
                    async.eachOf(callObj, function(subCallObj, one, subCallCb) {
                        if (settings &&
                            settings.api_calls &&
                            settings.api_calls.indexOf([service, one].join(':')) === -1) return subCallCb();

                        if (!collection[service][one]) collection[service][one] = {};
                        processTopCall(collection[service][one], service, subCallObj, subCallCb);
                    }, function() {
                        if (settings.identifier && postcalls[service].sendIntegration && postcalls[service].sendIntegration.enabled) {
                            if (!postcalls[service].sendIntegration.integrationReliesOn) {
                                integrationCall(collection, settings, service, [], [postcalls], function() {
                                    callCb();
                                });
                            } else {
                                services.push(service);
                                callCb();
                            }
                        } else {
                            callCb();
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

            // Tertiary Calls - tertiary calls that rely on secondary calls
            function(cb) {
                function processTopCall(collectionObj, service, subCallObj, subCallCb) {
                    // Loop through original properties
                    var regionsToLoop = parseCollection(subCallObj.reliesOnPath, collection);
                    if (regionsToLoop && Object.keys(regionsToLoop).length) {
                        // Loop through regions
                        async.eachOf(regionsToLoop, function(regionObj, region, regionCb) {
                            if (!collectionObj[region]) collectionObj[region] = {};
                            // Loop through the resources
                            async.eachOfLimit(regionObj, 5, function(resourceObj, resourceId, resourceCb){
                                function processResource(resourceData, resourceDataCb) {
                                    var localReq = {
                                        url: subCallObj.url,
                                        post: subCallObj.post,
                                        token: subCallObj.token,
                                        graph: subCallObj.graph,
                                        vault: subCallObj.vault,
                                        rateLimit: subCallObj.rateLimit,
                                        limit: subCallObj.limit
                                    };
                                    // Check and replace properties
                                    if (subCallObj.properties && subCallObj.properties.length) {
                                        subCallObj.properties.forEach(function(propToReplace) {
                                            if (resourceData[propToReplace]) {
                                                var re = new RegExp(`{${propToReplace}}`, 'g');
                                                localReq.url = subCallObj.url.replace(re, resourceData[propToReplace]);
                                            }
                                        });
                                    }

                                    // Add ID
                                    collectionObj[region][resourceData.id] = {};

                                    // Call and process API
                                    processCall(localReq, function(processCallErr, processCallData) {
                                        if (processCallErr) collectionObj[region][resourceData.id].err = processCallErr;
                                        if (processCallData) {
                                            if (processCallData.value) {
                                                collectionObj[region][resourceData.id].data = processCallData.value;
                                            } else {
                                                collectionObj[region][resourceData.id].data = processCallData;
                                            }
                                            helpers.reduceProperties(service, collectionObj[region][resourceData.id].data);
                                        }
                                        resourceDataCb();
                                    });
                                }

                                if (Array.isArray(resourceObj)) {
                                    async.eachLimit(resourceObj, 10, function(resourceData, resourceDataCb) {
                                        processResource(resourceData, resourceDataCb);
                                    }, function(){
                                        resourceCb();
                                    });
                                } else {
                                    if (resourceObj && resourceObj.data && resourceObj.data.length) {
                                        async.eachLimit(resourceObj.data, 10, function(resourceData, resourceDataCb) {
                                            processResource(resourceData, resourceDataCb);
                                        }, function() {
                                            resourceCb();
                                        });
                                    } else {
                                        resourceCb();
                                    }
                                }
                            }, function(){
                                regionCb();
                            });
                        }, function() {
                            subCallCb();
                        });
                    } else {
                        subCallCb();
                    }
                }

                async.eachOfLimit(tertiarycalls, 10, function(callObj, service, callCb) {
                    if (!collection[service]) collection[service] = {};
                    // Loop through sub-calls
                    async.eachOf(callObj, function(subCallObj, one, subCallCb) {
                        if (settings &&
                            settings.api_calls &&
                            settings.api_calls.indexOf([service, one].join(':')) === -1) return subCallCb();

                        if (!collection[service][one]) collection[service][one] = {};
                        if (subCallObj.url) {
                            processTopCall(collection[service][one], service, subCallObj, subCallCb);
                        } else {
                            // Go one level deeper
                            async.eachOf(subCallObj, function(innerCallObj, two, innerCb) {
                                if (settings &&
                                    settings.api_calls &&
                                    settings.api_calls.indexOf([service, one, two].join(':')) === -1) return subCallCb();

                                if (!collection[service][one][two]) collection[service][one][two] = {};
                                processTopCall(collection[service][one][two], service, innerCallObj, innerCb);
                            }, function() {
                                subCallCb();
                            });
                        }
                    }, function() {
                        if (settings.identifier && tertiarycalls[service].sendIntegration && tertiarycalls[service].sendIntegration.enabled) {
                            if (!tertiarycalls[service].sendIntegration.integrationReliesOn) {
                                integrationCall(collection, settings, service, [], [tertiarycalls], function() {
                                    callCb();
                                });
                            } else {
                                services.push(service);
                                callCb();
                            }
                        } else {
                            callCb();
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
            },

            // Process special calls with override functions
            function(cb) {
                async.eachOfLimit(specialcalls, 10, function(callObj, service, callCb) {
                    if (!collectors[service]) return callCb();
                    if (!collection[service]) collection[service] = {};
                    async.eachOfLimit(callObj, 1, function(subCallObj, one, subCallCb) {
                        if (settings &&
                            settings.api_calls &&
                            settings.api_calls.indexOf([service, one].join(':')) === -1) return subCallCb();
                        if (!collectors[service][one]) return subCallCb();
                        if (!collection[service][one]) collection[service][one] = {};
                        var reliesOn = {};
                        if (subCallObj.reliesOnPath) {
                            subCallObj.reliesOnPath.forEach(function(path){
                                reliesOn[path] = parseCollection(path, collection);
                            });
                        }
                        collectors[service][one](collection, reliesOn, function(){
                            if (subCallObj.rateLimit) {
                                setTimeout(function() {
                                    subCallCb();
                                }, subCallObj.rateLimit);
                            } else {
                                subCallCb();
                            }
                        });
                    }, function(){
                        if (settings.identifier && specialcalls[service].sendIntegration && specialcalls[service].sendIntegration.enabled) {
                            if (!specialcalls[service].sendIntegration.integrationReliesOn) {
                                integrationCall(collection, settings, service, [], [specialcalls], function() {
                                    callCb();
                                });
                            } else {
                                services.push(service);
                                callCb();
                            }
                        } else {
                            callCb();
                        }
                    });
                }, function() {
                    if (settings.identifier) {
                        async.each(services, function(serv, callB) {
                            integrationCall(collection, settings, serv, [], [specialcalls], callB);
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

            // Finalize
            function() {
                //console.log(JSON.stringify(collection, null,2));
                callback(null, collection);
            }
        ]);
    });
};

module.exports = collect;
