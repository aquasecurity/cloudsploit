/*********************
 Collector - The collector will query AWS APIs for the information required
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
var jsonsafe = require('fast-safe-stringify');

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
            arm: true,
            module: false
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
    vaults: {
        list: {
            api: "KeyVaultMangementClient",
            arm: true,
            module: true
        }
    },
    resources: {
        list: {
            api: "ResourceManagementClient",
            arm: true
        }
    },
    policyAssignments: {
        list: {
            api: "PolicyClient",
            arm: true
        }
    },
    webApps: {
        list: {
            api: "WebSiteManagementClient",
            arm: true
        }
    }
};

var postcalls = {
    storageAccounts: {
        listKeys: {
            api: "StorageManagementClient",
            reliesOnService: ['resourceGroups', 'storageAccounts'],
            reliesOnCall: ['list', 'list'],
            filterKey: ['resourceGroupName', 'name'],
            filterValue: ['resourceGroupName', 'name'],
            arm: true,
            module: false
        },
    },
    virtualMachineExtensions: {
        list: {
            api: "ComputeManagementClient",
            reliesOnService: ['resourceGroups', 'virtualMachines'],
            reliesOnCall: ['list', 'listAll'],
            filterKey: ['resourceGroupName', 'name'],
            filterValue: ['resourceGroupName', 'name'],
            arm: true
        }
    },
    activityLogAlerts: {
        listByResourceGroup: {
            api: "MonitorManagementClient",
            reliesOnService: ['resourceGroups'],
            reliesOnCall: ['list'],
            filterKey: ['resourceGroupName'],
            filterValue: ['resourceGroupName'],
            arm: true,
            module: false
        }
    },
    vaults: {
        listByResourceGroup: {
            api: "KeyVaultMangementClient",
            reliesOnService: ['resourceGroups'],
            reliesOnCall: ['list'],
            filterKey: ['resourceGroupName'],
            filterValue: ['resourceGroupName'],
            arm: true
        }
    },
    blobContainers: {
        list: {
            api: "StorageManagementClient",
            reliesOnService: ['resourceGroups', 'storageAccounts'],
            reliesOnCall: ['list', 'list'],
            filterKey: ['resourceGroupName', 'name'],
            filterValue: ['resourceGroupName', 'name'],
            arm: true
        }
    },
    webApps: {
        get: {
            api: "WebSiteManagementClient",
            reliesOnService: ['webApps', 'webApps'],
            reliesOnCall: ['list', 'list'],
            filterKey: ['resourceGroupName', 'name'],
            filterValue: ['resourceGroupName', 'name'],
            arm: true
        }
    }
};

var finalcalls = {
    BlobService: {
        listContainersSegmented: {
            api: "StorageServiceClient",
            reliesOnService: ['storageAccounts', 'storageAccounts'],
            reliesOnCall: ['list', 'listKeys'],
            filterKey: ['name', 'keys'],
            filterValue: ['name', 'value'],
            filterListKeys: [false, true],
            arm: false,
            module: true
        }
    },
    FileService: {
        listSharesSegmented: {
            api: "StorageServiceClient",
            reliesOnService: ['storageAccounts', 'storageAccounts'],
            reliesOnCall: ['list', 'listKeys'],
            filterKey: ['name', 'keys'],
            filterValue: ['name', 'value'],
            filterListKeys: [false, true],
            arm: false,
            module: true
        }
    },
    TableService: {
        listTablesSegmented: {
            api: "StorageServiceClient",
            reliesOnService: ['storageAccounts', 'storageAccounts'],
            reliesOnCall: ['list', 'listKeys'],
            filterKey: ['name', 'keys'],
            filterValue: ['name', 'value'],
            filterListKeys: [false, true],
            arm: false,
            module: true
        }
    },
    QueueService: {
        listQueuesSegmented: {
            api: "StorageServiceClient",
            reliesOnService: ['storageAccounts', 'storageAccounts'],
            reliesOnCall: ['list', 'listKeys'],
            filterKey: ['name', 'keys'],
            filterValue: ['name', 'value'],
            filterListKeys: [false, true],
            arm: false,
            module: true
        }
    },
    KeyVaultClient: {
        getSecrets: {
            api: "KeyVaultClient",
            reliesOnService: ['vaults'],
            reliesOnCall: ['listByResourceGroup'],
            filterKey: ['properties'],
            filterValue: ['[0.{properties/vaultUri'],
            arm: false,
            module: true
        }
    }
};

var postfinalcalls = {
    FileService: {
        getShareAcl: {
            api: "StorageServiceClient",
            reliesOnService: ['storageAccounts', 'storageAccounts', 'FileService'],
            reliesOnCall: ['list', 'listKeys', 'listSharesSegmented'],
            filterKey: ['name', 'keys', 'name'],
            filterValue: ['name', 'value', 'name'],
            entryKey: ['', '', 'fileName'],
            filterListKeys: [false, true, false],
            arm: false,
            module: true
        }
    },
    TableService: {
        getTableAcl: {
            api: "StorageServiceClient",
            reliesOnService: ['storageAccounts', 'storageAccounts', 'TableService'],
            reliesOnCall: ['list', 'listKeys', 'listTablesSegmented'],
            filterKey: ['name', 'keys', 'table'],
            filterValue: ['name', 'value', 'name'],
            entryKey: ['', '', 'tableName'],
            filterListKeys: [false, true, false],
            arm: false,
            module: true
        }
    },
    QueueService: {
        getQueueAcl: {
            api: "StorageServiceClient",
            reliesOnService: ['storageAccounts', 'storageAccounts', 'QueueService'],
            reliesOnCall: ['list', 'listKeys', 'listQueuesSegmented'],
            filterKey: ['name', 'keys', 'name'],
            filterValue: ['name', 'value', 'name'],
            entryKey: ['', '', 'queueName'],
            filterListKeys: [false, true, false],
            arm: false,
            module: true
        }
    }
};

var collection = {};

// Loop through all of the top-level collectors for each service

var processCall = function (AzureConfig, settings, locations, call, service, serviceCb) {
    // Loop through each of the service's functions
    async.eachOfLimit(call, 10, function (callObj, callKey, callCb) {
        if (!collection[service][callKey]) collection[service][callKey] = {};

        callObj.collection = collection;

        var LocalAzureConfig = JSON.parse(JSON.stringify(AzureConfig));
        LocalAzureConfig.service = service;

        var executor = new helpers.AzureExecutor(LocalAzureConfig);
        executor.run(collection, service, callObj, callKey, function (err, data) {
            if ((err && err.length == undefined) == true || (err && err.length !== undefined && err.length > 0) == true) {
                collection[service][callKey].err = err;
            }

            if (!data || data.length == 0) {
                return callCb();
            }

            var locations = helpers.locations(false)[service];

            for (l in locations) {
                if (!collection[service][callKey][locations[l]]) {
                    collection[service][callKey][locations[l]] = { data: [] };
                }
            }

            var locationsInArray = [];
            for (var d = 0; d < data.length; d++) {
                if (data[d].location) {
                    data[d].location = data[d].location.replace(/ /g, "").toLowerCase();
	                var locationExists = locationsInArray.filter(loc => loc == data[d].location);
	                var locationIsValid = locations.filter(loc => loc == data[d].location);
	                if (locationExists && locationExists.length == 0 &&
	                    locationIsValid && locationIsValid.length > 0) {
	                    locationsInArray.push(data[d].location);
	                }
				} else {
                    data[d].location = "global";
                    locationsInArray.push(data[d].location);
                }
            }

            if (locationsInArray && locationsInArray.length > 0) {
                for (locationSelected in locationsInArray) {
                    var dataToPush = data.filter((d) => {
                        return d.location == locationsInArray[locationSelected];
                    });

                    if (collection[service][callKey][locationsInArray[locationSelected]] == undefined) {
                        collection[service][callKey][locationsInArray[locationSelected]] = {};
                    }

                    collection[service][callKey][locationsInArray[locationSelected]].data = dataToPush;
                }
            } else {
                if (data.length > 0) {
                    collection[service][callKey]['unknown'] = {};
                    collection[service][callKey]['unknown'].data = data;
                }
            }

            callCb();
        });
    }, function () {
        serviceCb();
    });
};

// Loop through all of the top-level collectors for each service
var collect = function (AzureConfig, settings, callback) {
    AzureConfig.maxRetries = 5;
    AzureConfig.retryDelayOptions = { base: 300 };
    var settings = settings;
    var locations = helpers.locations(settings.govcloud);

    async.eachOfLimit(calls, 10, function (call, service, serviceCbcall) {
        var service = service;
        if (settings.api_calls && settings.api_calls.indexOf(service + ':' + Object.keys(call)[0]) === -1) return serviceCbcall();
        if (!collection[service]) collection[service] = {};

        processCall(AzureConfig, settings, locations, call, service, function () {
            serviceCbcall();
        });
    }, function () {
        // Now loop through the follow up calls
        async.eachOfLimit(postcalls, 10, function (postCall, service, serviceCbpostCall) {
            var service = service;
            if (settings.api_calls && settings.api_calls.indexOf(service + ':' + Object.keys(postCall)[0]) === -1) return serviceCbpostCall();
            if (!collection[service]) collection[service] = {};

            processCall(AzureConfig, settings, locations, postCall, service, function () {
                serviceCbpostCall();
            });
        }, function () {
            // Now loop through the follow up calls
            async.eachOfLimit(finalcalls, 10, function (finalCall, service, serviceCbfinalCall) {
                var service = service;
                if (settings.api_calls && settings.api_calls.indexOf(service + ':' + Object.keys(finalCall)[0]) === -1) return serviceCbfinalCall();
                if (!collection[service]) collection[service] = {};

                processCall(AzureConfig, settings, locations, finalCall, service, function () {
                    serviceCbfinalCall();
                });

            }, function () {
                // Now loop through the follow up calls
                async.eachOfLimit(postfinalcalls, 10, function (postFinalCall, service, serviceCbpostFinalCall) {
                    var service = service;
                    if (settings.api_calls && settings.api_calls.indexOf(service + ':' + Object.keys(postFinalCall)[0]) === -1) return serviceCbpostFinalCall();
                    if (!collection[service]) collection[service] = {};

                    processCall(AzureConfig, settings, locations, postFinalCall, service, function () {
                        serviceCbpostFinalCall();
                    });

                }, function () {
                    //console.log(JSON.stringify(collection, null, 2));
                    collection = JSON.parse(jsonsafe(collection));
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
    }, function () {
        //console.log(JSON.stringify(collection, null, 2));
        callback(null, collection);
    });

};

module.exports = collect;