/*********************
 Collector - The collector will query AWS APIs for the information required
 to run the CloudSploit scans. This data will be returned in the callback
 as a JSON object.

 Arguments:
 - AWSConfig: If using an access key/secret, pass in the config object. Pass null if not.
 - settings: custom settings for the scan. Properties:
 - skip_locations: (Optional) List of locations to skip
 - api_calls: (Optional) If provided, will only query these APIs.
 - Example:
 {
     "skip_locations": ["East US", "West US"],
     "api_calls": ["EC2:describeInstances", "S3:listBuckets"]
 }
 - callback: Function to call when the collection is complete
 *********************/

var async = require('async');
var util = require('util');

var helpers = require(__dirname + '/../../helpers/azure');
var collectors = require(__dirname + '/../../collectors/azure');

var globalServices = [
    'storageManagement'
];

var calls = {
    resourceGroups: {
        list: {
            api: "ResourceManagementClient",
            arm: true
        }
    },
    storageAccounts: {
        list: {
            api: "StorageManagementClient",
            arm: true
        }
    },
    virtualMachines: {
        listAll: {
            api: "ComputeManagementClient",
            arm: true
        }
    },
    disks: {
        list: {
            api: "ComputeManagementClient",
            arm: true
        }
    },
};

var postcalls = [
    {
        storageAccounts: {
            listKeys: {
                api: "StorageManagementClient",
                reliesOnService: ['resourceGroups', 'storageAccounts'],
                reliesOnCall: ['list', 'list'],
                filterKey: ['name', 'name'],
                filterValue: ['name', 'name'],
                arm: true
            },
        },
        virtualMachineExtensions: {
            list: {
                api: "ComputeManagementClient",
                reliesOnService: ['resourceGroups', 'virtualMachines'],
                reliesOnCall: ['list', 'listAll'],
                filterKey: ['name', 'name'],
                filterValue: ['name', 'name'],
                arm: true
            }
        }
    }
];

var finalcalls = [
    {
        BlobService: {
            listContainersSegmented: {
                api: "StorageServiceClient",
                reliesOnService: ['storageAccounts','storageAccounts'],
                reliesOnCall: ['list','listKeys'],
                filterKey: ['name','keys'],
                filterValue: ['name','value'],
                arm: false
            }
        },
        FileService: {
            listSharesSegmented: {
                api: "StorageServiceClient",
                reliesOnService: ['storageAccounts','storageAccounts'],
                reliesOnCall: ['list','listKeys'],
                filterKey: ['name','keys'],
                filterValue: ['name','value'],
                arm: false
            }
        },
        TableService: {
            listTablesSegmented: {
                api: "StorageServiceClient",
                reliesOnService: ['storageAccounts','storageAccounts'],
                reliesOnCall: ['list','listKeys'],
                filterKey: ['name','keys'],
                filterValue: ['name','value'],
                arm: false
            }
        },
        QueueService: {
            listQueuesSegmented: {
                api: "StorageServiceClient",
                reliesOnService: ['storageAccounts','storageAccounts'],
                reliesOnCall: ['list','listKeys'],
                filterKey: ['name','keys'],
                filterValue: ['name','value'],
                arm: false
            }
        },
    }
];

var postfinalcalls = [
    {
        FileService: {
            getShareAcl: {
                api: "StorageServiceClient",
                reliesOnService: ['storageAccounts','storageAccounts','FileService'],
                reliesOnCall: ['list','listKeys','listSharesSegmented'],
                filterKey: ['name','keys','name'],
                filterValue: ['name','value','name'],
                arm: false
            }
        }
    }
];

var collection = {};

// Loop through all of the top-level collectors for each service
var collect = function (AzureConfig, settings, callback) {
    AzureConfig.maxRetries = 5;
    AzureConfig.retryDelayOptions = {base: 300};

    var locations = helpers.locations(settings.govcloud);
    
    async.eachOfLimit(calls, 10, function (call, service, serviceCb) {
        var azureService = service;
        if (!collection[azureService]) collection[azureService] = {};

        // Loop through each of the service's functions
        async.eachOfLimit(call, 10, function (callObj, callKey, callCb) {
            if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return callCb();
            if (!collection[azureService][callKey]) collection[azureService][callKey] = {};

            async.eachLimit(locations[azureService], helpers.MAX_LOCATIONS_AT_A_TIME, function (location, locationCb) {
                if (settings.skip_locations &&
                    settings.skip_locations.indexOf(location) > -1 &&
                    globalServices.indexOf(service) === -1) return locationCb();
                if (!collection[azureService][callKey][location]) collection[azureService][callKey][location] = {};

                var LocalAzureConfig = JSON.parse(JSON.stringify(AzureConfig));
                LocalAzureConfig.location = location;
                LocalAzureConfig.service = service;

                if (callObj.override) {
                    collectors[azureService][callKey](LocalAWSConfig, collection, function () {
                        if (callObj.rateLimit) {
                            setTimeout(function () {
                                locationCb();
                            }, callObj.rateLimit);
                        } else {
                            locationCb();
                        }
                    });
                } else {
                    var executor = new helpers.AzureExecutor(LocalAzureConfig);
                    executor.runarm(collection, callObj, callKey, function(err, data){
                        if (err) {
                            collection[azureService][callKey][location].err = err;
                        }

                        if (!data) return locationCb();

                        collection[azureService][callKey][location].data = data;

                        if (callObj.rateLimit) {
                            setTimeout(function(){
                                locationCb();
                            }, callObj.rateLimit);
                        } else {
                            locationCb();
                        }
                    });
                }
            }, function () {
                callCb();
            });
        }, function () {
            serviceCb();
        });
    }, function () {
        // Now loop through the follow up calls
        async.eachSeries(postcalls, function (postcallObj, postcallCb) {
            async.eachOfLimit(postcallObj, 10, function (serviceObj, service, serviceCb) {
                var azureService = service;
                if (!collection[azureService]) collection[azureService] = {};

                async.eachOfLimit(serviceObj, 1, function (callObj, callKey, callCb) {
                    if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return callCb();
                    if (!collection[azureService][callKey]) collection[azureService][callKey] = {};

                    async.eachLimit(locations[azureService], helpers.MAX_LOCATIONS_AT_A_TIME, function (location, locationCb) {
                        if (settings.skip_locations &&
                            settings.skip_locations.indexOf(location) > -1 &&
                            globalServices.indexOf(service) === -1) return locationCb();
                        if (!collection[azureService][callKey][location]) collection[azureService][callKey][location] = {};

                        if (callObj.reliesOnService.length) {
                            // Ensure multiple pre-requisites are met
                            for (reliedService in callObj.reliesOnService){
                                if (callObj.reliesOnService[reliedService] && !collection[callObj.reliesOnService[reliedService]]) return locationCb();

                                if (callObj.reliesOnService[reliedService] &&
                                    (!collection[callObj.reliesOnService[reliedService]] ||
                                    !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]] ||
                                    !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]][location] ||
                                    !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]][location].data ||
                                    !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]][location].data.length)) return locationCb();
                                    
                            }
                        } else {
                            // Ensure pre-requisites are met
                            if (callObj.reliesOnService && !collection[callObj.reliesOnService]) return locationCb();

                            if (callObj.reliesOnCall &&
                                (!collection[callObj.reliesOnService] ||
                                !collection[callObj.reliesOnService][callObj.reliesOnCall] ||
                                !collection[callObj.reliesOnService][callObj.reliesOnCall][location] ||
                                !collection[callObj.reliesOnService][callObj.reliesOnCall][location].data ||
                                !collection[callObj.reliesOnService][callObj.reliesOnCall][location].data.length)) return locationCb();
                        }

                        var LocalAzureConfig = JSON.parse(JSON.stringify(AzureConfig));
                        LocalAzureConfig.location = location;
                        LocalAzureConfig.service = service;

                        if (callObj.deletelocation) {
                            //delete LocalAWSConfig.location;
                            LocalAzureConfig.location = settings.govcloud ? 'us-gov-west-1' : 'us-east-1';
                        } else {
                            LocalAzureConfig.location = location;
                        }
                        if (callObj.signatureVersion) LocalAzureConfig.signatureVersion = callObj.signatureVersion;

                        if (callObj.override) {
                            collectors[azureService][callKey](LocalAzureConfig, collection, function () {
                                if (callObj.rateLimit) {
                                    setTimeout(function () {
                                        locationCb();
                                    }, callObj.rateLimit);
                                } else {
                                    locationCb();
                                }
                            });
                        } else {
                            var executor = new helpers.AzureExecutor(LocalAzureConfig);
                            executor.runarm(collection, callObj, callKey, function(err, data){
                                if (err) {
                                    collection[azureService][callKey][location].err = err;
                                }

                                if (!data) return locationCb();

                                collection[azureService][callKey][location].data = data;

                                if (callObj.rateLimit) {
                                    setTimeout(function(){
                                        locationCb();
                                    }, callObj.rateLimit);
                                } else {
                                    locationCb();
                                }
                            });
                        }
                    }, function () {
                        callCb();
                    });
                }, function () {
                    serviceCb();
                });
            }, function () {
                postcallCb();
            });
        }, function () {
            // Now loop through the final calls
            async.eachSeries(finalcalls, function (finalcallObj, finalcallCb) {
                async.eachOfLimit(finalcallObj, 10, function (serviceObj, service, serviceCb) {
                    var azureService = service;
                    if (!collection[azureService]) collection[azureService] = {};

                    async.eachOfLimit(serviceObj, 1, function (callObj, callKey, callCb) {
                        if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return callCb();
                        if (!collection[azureService][callKey]) collection[azureService][callKey] = {};

                        async.eachLimit(locations[azureService], helpers.MAX_LOCATIONS_AT_A_TIME, function (location, locationCb) {
                            if (settings.skip_locations &&
                                settings.skip_locations.indexOf(location) > -1 &&
                                globalServices.indexOf(service) === -1) return locationCb();
                            if (!collection[azureService][callKey][location]) collection[azureService][callKey][location] = {};

                            if (callObj.reliesOnService.length) {
                                // Ensure multiple pre-requisites are met
                                for (reliedService in callObj.reliesOnService){
                                    if (callObj.reliesOnService[reliedService] && !collection[callObj.reliesOnService[reliedService]]) return locationCb();

                                    if (callObj.reliesOnCall[reliedService] &&
                                        (!collection[callObj.reliesOnService[reliedService]] ||
                                            !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]] ||
                                            !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]][location] ||
                                            !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]][location].data )) return locationCb();
                                }
                            } else {
                                // Ensure pre-requisites are met
                                if (callObj.reliesOnService && !collection[callObj.reliesOnService]) return locationCb();

                                if (callObj.reliesOnCall &&
                                    (!collection[callObj.reliesOnService] ||
                                        !collection[callObj.reliesOnService][callObj.reliesOnCall] ||
                                        !collection[callObj.reliesOnService][callObj.reliesOnCall][location] ||
                                        !collection[callObj.reliesOnService][callObj.reliesOnCall][location].data )) return locationCb();
                            }

                            var LocalAzureConfig = JSON.parse(JSON.stringify(AzureConfig));
                            LocalAzureConfig.location = location;
                            LocalAzureConfig.service = service;

                            if (callObj.deletelocation) {
                                //delete LocalAWSConfig.location;
                                LocalAzureConfig.location = settings.govcloud ? 'us-gov-west-1' : 'us-east-1';
                            } else {
                                LocalAzureConfig.location = location;
                            }
                            if (callObj.signatureVersion) LocalAzureConfig.signatureVersion = callObj.signatureVersion;

                            if (callObj.override) {
                                collectors[azureService][callKey](LocalAzureConfig, collection, function () {
                                    if (callObj.rateLimit) {
                                        setTimeout(function () {
                                            locationCb();
                                        }, callObj.rateLimit);
                                    } else {
                                        locationCb();
                                    }
                                });
                            } else {
                                var executor = new helpers.AzureExecutor(LocalAzureConfig);
                                if (callObj.arm){
                                    executor.runarm(collection, callObj, callKey, function(err, data){
                                        if (err) {
                                            collection[azureService][callKey][location].err = err;
                                        }

                                        if (!data) return locationCb();

                                        collection[azureService][callKey][location].data = data;

                                        if (callObj.rateLimit) {
                                            setTimeout(function(){
                                                locationCb();
                                            }, callObj.rateLimit);
                                        } else {
                                            locationCb();
                                        }
                                    });
                                } else {
                                    executor.runasm(collection, callObj, callKey, function(err, data){
                                        if (err) {
                                            collection[azureService][callKey][location].err = err;
                                        }

                                        if (!data) return locationCb();

                                        collection[azureService][callKey][location].data = data;

                                        if (callObj.rateLimit) {
                                            setTimeout(function(){
                                                locationCb();
                                            }, callObj.rateLimit);
                                        } else {
                                            locationCb();
                                        }
                                    });
                                }
                            }
                        }, function () {
                            callCb();
                        });
                    }, function () {
                        serviceCb();
                    });
                }, function () {
                    finalcallCb();
                });
            }, function () {
                // Now loop through the postfinal calls
                async.eachSeries(postfinalcalls, function (postfinalcallObj, postfinalcallCb) {
                    async.eachOfLimit(postfinalcallObj, 10, function (serviceObj, service, serviceCb) {
                        var azureService = service;
                        if (!collection[azureService]) collection[azureService] = {};

                        async.eachOfLimit(serviceObj, 1, function (callObj, callKey, callCb) {
                            if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return callCb();
                            if (!collection[azureService][callKey]) collection[azureService][callKey] = {};

                            async.eachLimit(locations[azureService], helpers.MAX_LOCATIONS_AT_A_TIME, function (location, locationCb) {
                                if (settings.skip_locations &&
                                    settings.skip_locations.indexOf(location) > -1 &&
                                    globalServices.indexOf(service) === -1) return locationCb();
                                if (!collection[azureService][callKey][location]) collection[azureService][callKey][location] = {};

                                if (callObj.reliesOnService.length) {
                                    // Ensure multiple pre-requisites are met
                                    for (reliedService in callObj.reliesOnService){
                                        if (callObj.reliesOnService[reliedService] && !collection[callObj.reliesOnService[reliedService]]) return locationCb();

                                        if (callObj.reliesOnCall[reliedService] &&
                                            (!collection[callObj.reliesOnService[reliedService]] ||
                                                !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]] ||
                                                !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]][location] ||
                                                !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]][location].data )) return locationCb();
                                    }
                                } else {
                                    // Ensure pre-requisites are met
                                    if (callObj.reliesOnService && !collection[callObj.reliesOnService]) return locationCb();

                                    if (callObj.reliesOnCall &&
                                        (!collection[callObj.reliesOnService] ||
                                            !collection[callObj.reliesOnService][callObj.reliesOnCall] ||
                                            !collection[callObj.reliesOnService][callObj.reliesOnCall][location] ||
                                            !collection[callObj.reliesOnService][callObj.reliesOnCall][location].data )) return locationCb();
                                }

                                var LocalAzureConfig = JSON.parse(JSON.stringify(AzureConfig));
                                LocalAzureConfig.location = location;
                                LocalAzureConfig.service = service;

                                if (callObj.deletelocation) {
                                    //delete LocalAWSConfig.location;
                                    LocalAzureConfig.location = settings.govcloud ? 'us-gov-west-1' : 'us-east-1';
                                } else {
                                    LocalAzureConfig.location = location;
                                }
                                if (callObj.signatureVersion) LocalAzureConfig.signatureVersion = callObj.signatureVersion;

                                if (callObj.override) {
                                    collectors[azureService][callKey](LocalAzureConfig, collection, function () {
                                        if (callObj.rateLimit) {
                                            setTimeout(function () {
                                                locationCb();
                                            }, callObj.rateLimit);
                                        } else {
                                            locationCb();
                                        }
                                    });
                                } else {
                                    var executor = new helpers.AzureExecutor(LocalAzureConfig);
                                    if (callObj.arm){
                                        executor.runarm(collection, callObj, callKey, function(err, data){
                                            if (err) {
                                                collection[azureService][callKey][location].err = err;
                                            }

                                            if (!data) return locationCb();

                                            collection[azureService][callKey][location].data = data;

                                            if (callObj.rateLimit) {
                                                setTimeout(function(){
                                                    locationCb();
                                                }, callObj.rateLimit);
                                            } else {
                                                locationCb();
                                            }
                                        });
                                    } else {
                                        executor.runasm(collection, callObj, callKey, function(err, data){
                                            if (err) {
                                                collection[azureService][callKey][location].err = err;
                                            }

                                            if (!data) return locationCb();

                                            collection[azureService][callKey][location].data = data;

                                            if (callObj.rateLimit) {
                                                setTimeout(function(){
                                                    locationCb();
                                                }, callObj.rateLimit);
                                            } else {
                                                locationCb();
                                            }
                                        });
                                    }
                                }
                            }, function () {
                                callCb();
                            });
                        }, function () {
                            serviceCb();
                        });
                    }, function () {
                        postfinalcallCb();
                    });
                }, function () {
                    //console.log(JSON.stringify(collection, null, 2));
                    callback(null, collection);
                });
            }, function () {
                //console.log(JSON.stringify(collection, null, 2));
                callback(null, collection);
            });
        }, function () {
            //console.log(JSON.stringify(collection, null, 2));
            callback(null, collection);
        });
    });
};

module.exports = collect;