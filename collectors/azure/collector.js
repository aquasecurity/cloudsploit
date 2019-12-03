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
var jsonsafe = require('fast-safe-stringify');

var helpers = require(__dirname + '/../../helpers/azure');

var calls = {
    resourceGroups: {
        list: {
            api: "ResourceManagementClient",
            arm: true
        }
    },
    activityLogAlerts: {
        listBySubscriptionId: {
            api: "MonitorManagementClient",
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
    virtualNetworks: {
        listAll: {
            api: "NetworkManagementClient",
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
    networkSecurityGroups: {
        listAll: {
            api: "NetworkManagementClient",
            arm: true
        }
    },
    activityLogAlerts: {
        listBySubscriptionId: {
            api: "MonitorManagementClient",
            arm: true
        }
    },
    vaults: {
        list: {
            api: "KeyVaultManagementClient",
            arm: true
        }
    },
    resources: {
        list: {
            api: "ResourceManagementClient",
            arm: true
        }
    },
    managedClusters: {
        list: {
            api: "ContainerServiceClient",     
            arm: true
        }
    },
    networkWatchers: {
        listAll: {
            api: "NetworkManagementClient",
            arm: true
        }
    },
    servers: {
        sql: {
            list: {
                api: "SQLManagementClient",
                arm: true
            }
        },
        mysql: {
            list: {
                api: "MySQLManagementClient",
                arm: true
            }
        },
        postgres: {
            list: {
                api: "PostgresClient",
                arm: true
            }
        },
        manyApi: true
    },
    policyAssignments: {
        list: {
            api: "PolicyClient",
            arm: true
        }
    },
    policyDefinitions: {
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
    },
    logProfiles: {
        list: {
            api: "MonitorManagementClient",
            arm: true
        }
    },
    profiles: {
        list: {
            api: "CdnManagementClient",
            arm: true
        }
    },
    autoProvisioningSettings: {
        list: {
            api: "SecurityCenterClient",
            arm: true,
            ascLoc: true
        }
    },
    securityContacts: {
        list: {
            api: "SecurityCenterClient",
            arm: true,
            ascLoc: true
        }
    },
    subscriptions: {
        listLocations: {
            api: "SubscriptionClient",
            arm: true,
            noSubscription: true
        }
    },
    roleDefinitions: {
        list: {
            api: "AuthorizationClient",
            arm: true,
            subscription: true
        }
    },
    managementLocks: {
        listAtSubscriptionLevel: {
            api: "ManagementLockClient",
            arm: true
        }
    },
    loadBalancers: {
        listAll: {
            api: "NetworkManagementClient",
            arm: true
        }
    },
    users: {
        list: {
            api: "AzureGraphClient",
            arm: true,
            ad: true
        }
    },
    registries: {
        list: {
            api: "ContainerRegistryClient",
            arm: true
        }
    },
    pricings: {
        list: {
            api: "SecurityCenterClient",
            arm: true,
            ascLoc: true
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
    availabilitySets: {
        list: {
            api: "ComputeManagementClient",
            reliesOnService: ['resourceGroups'],
            reliesOnCall: ['list'],
            filterKey: ['resourceGroupName'],
            filterValue: ['resourceGroupName'],
            arm: true,
        }
    },
    autoscaleSettings: {
        listByResourceGroup: {
            api: "MonitorManagementClient",
            reliesOnService: ['resourceGroups'],
            reliesOnCall: ['list'],
            filterKey: ['resourceGroupName'],
            filterValue: ['resourceGroupName'],
            arm: true
        }
    },
    networkSecurityGroups: {
        list: {
            api: "NetworkManagementClient",
            reliesOnService: ['resourceGroups'],
            reliesOnCall: ['list'],
            filterKey: ['resourceGroupName'],
            filterValue: ['resourceGroupName'],
            arm: true
        }
    },
    networkSecurityGroups: {
        list: {
            api: "NetworkManagementClient",
            reliesOnService: ['resourceGroups'],
            reliesOnCall: ['list'],
            filterKey: ['resourceGroupName'],
            filterValue: ['resourceGroupName'],
            arm: true
        }
    },
    serverBlobAuditingPolicies: {
        get: {
            api: "SQLManagementClient",
            reliesOnService: ['resourceGroups', 'servers'],
            reliesOnSubService: [undefined, 'sql'],
            reliesOnCall: ['list', 'list'],
            filterKey: ['resourceGroupName', 'name'],
            filterValue: ['resourceGroupName', 'name'],
            arm: true,
        }
    },
    configurations: {
        listByServer: {
            api: "PostgresClient",
            reliesOnService: ['resourceGroups', 'servers'],
            reliesOnSubService: [undefined, 'postgres'],
            reliesOnCall: ['list', 'list'],
            filterKey: ['resourceGroupName', 'name'],
            filterValue: ['resourceGroupName', 'name'],
            arm: true,

        }
    },
    diagnosticSettingsOperations: {
        nsg: {
            list: {
                api: "MonitorManagementClient",
                reliesOnService: ['networkSecurityGroups'],
                reliesOnCall: ['listAll'],
                filterKey: ['resourceUri'],
                filterValue: ['id'],
                arm: true
            },
        },
        lb: {
            list: {
                api: "MonitorManagementClient",
                reliesOnService: ['loadBalancers'],
                reliesOnCall: ['listAll'],
                filterKey: ['id'],
                filterValue: ['id'],
                arm: true
            },
        },
        kv: {
            list: {
                api: "MonitorManagementClient",
                reliesOnService: ['vaults'],
                reliesOnCall: ['list'],
                filterKey: ['id'],
                filterValue: ['id'],
                arm: true
            }
        },
        manyApi: true
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
            api: "KeyVaultManagementClient",
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
    encryptionProtectors: {
        get: {
            api: "SQLManagementClient",
            reliesOnService: ['resourceGroups', 'servers'],
            reliesOnSubService: [undefined, 'sql'],
            reliesOnCall: ['list', 'list'],
            filterKey: ['resourceGroupName', 'serverName'],
            filterValue: ['resourceGroupName', 'name'],
            arm: true,
        },
    },
    webApps: {
        getAuthSettings: {
            api: "WebSiteManagementClient",
            reliesOnService: ['webApps', 'webApps'],
            reliesOnCall: ['list', 'list'],
            filterKey: ['resourceGroup', 'name'],
            filterValue: ['resourceGroup', 'name'],
            arm: true
        },
        listConfigurations: {
            api: "WebSiteManagementClient",
            reliesOnService: ['webApps', 'webApps'],
            reliesOnCall: ['list', 'list'],
            filterKey: ['resourceGroup', 'name'],
            filterValue: ['resourceGroup', 'name'],
            arm: true
        },
        get: {
            api: "WebSiteManagementClient",
            reliesOnService: ['webApps', 'webApps'],
            reliesOnCall: ['list', 'list'],
            filterKey: ['resourceGroupName', 'name'],
            filterValue: ['resourceGroupName', 'name'],
            arm: true
        }
    },
    servers: {
        listByResourceGroup: {
            api: "SQLManagementClient",
            reliesOnService: ['resourceGroups'],
            reliesOnCall: ['list'],
            filterKey: ['resourceGroupName'],
            filterValue: ['resourceGroupName'],
            arm: true,
            module: false,
        }
    },
    endpoints: {
        listByProfile: {
            api: "CdnManagementClient",
            reliesOnService: ['resourceGroups', 'profiles'],
            reliesOnCall: ['list', 'list'],
            filterKey: ['resourceGroupName', 'profileName'],
            filterValue: ['resourceGroupName', 'name'],
            arm: true
        },
    },
    KeyVaultClient: {
        getKeys: {
            api: "KeyVaultClient",
            reliesOnService: ['vaults'],
            reliesOnCall: ['list'],
            filterKey: ['name'],
            filterValue: ['name'],
            arm: false,
            keyVault: true
        },
        getSecrets: {
            api: "KeyVaultClient",
            reliesOnService: ['vaults'],
            reliesOnCall: ['list'],
            filterKey: ['name'],
            filterValue: ['name'],
            arm: false,
            keyVault: true
        }
    },
    loadBalancers: {
        list: {
            api: "NetworkManagementClient",
            reliesOnService: ['resourceGroups'],
            reliesOnCall: ['list'],
            filterKey: ['resourceGroupName'],
            filterValue: ['resourceGroupName'],
            arm: true
        }
    },
    databases: {
        listByServer: {
            api: "SQLManagementClient",
            reliesOnService: ['resourceGroups','servers'],
            reliesOnSubService: [undefined, 'sql'],
            reliesOnCall: ['list','list'],
            filterKey: ['resourceGroupName','serverName'],
            filterValue: ['resourceGroupName','name'],
            arm: true
        },
    },
    serverAzureADAdministrators: {
        listByServer: {
            api: "SQLManagementClient",
            reliesOnService: ['resourceGroups','servers'],
            reliesOnSubService: [undefined, 'sql'],
            reliesOnCall: ['list','list'],
            filterKey: ['resourceGroupName','serverName'],
            filterValue: ['resourceGroupName','name'],
            arm: true
        }
    },
	virtualMachineScaleSets: {
        list: {
            api: "ComputeManagementClient",
            reliesOnService: ['resourceGroups'],
            reliesOnCall: ['list'],
            filterKey: ['resourceGroupName'],
            filterValue: ['resourceGroupName'],
            arm: true
        }
    },
    usages: {
        list: {
            api: "NetworkManagementClient",
            reliesOnService: ['subscriptions'],
            reliesOnCall: ['listLocations'],
            filterKey: ['name'],
            filterValue: ['name'],
            arm: true
        }
    },
    firewallRules: {
        listByServer: {
            api: "SQLManagementClient",
            reliesOnService: ['resourceGroups','servers'],
            reliesOnSubService: [undefined, 'sql'],
            reliesOnCall: ['list', 'list'],
            filterKey: ['resourceGroupName', 'serverName'],
            filterValue: ['resourceGroupName', 'name'],
            arm: true
        }
    },
    managedClusters: {
        getUpgradeProfile: {
            api: "ContainerServiceClient",
            reliesOnService: ['resourceGroups', 'managedClusters'],
            reliesOnCall: ['list', 'list'],
            filterKey: ['resourceGroupName', 'recourceName'],
            filterValue: ['resourceGroupName','name'],
            arm: true
        }
    }
};

var finalcalls = {
    securityRules: {
        list: {
            api: "NetworkManagementClient",
            reliesOnService: ['resourceGroups', 'networkSecurityGroups'],
            reliesOnCall: ['list', 'list'],
            filterKey: ['resourceGroupName', 'networkSecurityGroupName'],
            filterValue: ['resourceGroupName','name'],
            arm: true
        }
    },
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
    },
    diagnosticSettingsOperations: {
        list: {
            api: "MonitorManagementClient",
            reliesOnService: ['endpoints'],
            reliesOnCall: ['listByProfile'],
            filterKey: ['id'],
            filterValue: ['id'],
            arm: true
        }
    },
    serverSecurityAlertPolicies: {
        listByServer: {
            api: "SQLManagementClient",
            reliesOnService: ['resourceGroups', 'servers'],
            reliesOnCall: ['list', 'listByResourceGroup'],
            filterKey: ['resourceGroupName', 'serverName'],
            filterValue: ['resourceGroupName', 'name'],
            arm: true,
            module: false,
        }
    },
    origins: {
        listByEndpoint: {
            api: "CdnManagementClient",
            reliesOnService: ['resourceGroups', 'profiles', 'endpoints'],
            reliesOnCall: ['list', 'list', 'listByProfile'],
            filterKey: ['resourceGroupName', 'profileName', 'endpointName'],
            filterValue: ['resourceGroupName', 'profileName', 'name'],
            arm: true,
        }
    },
    databaseBlobAuditingPolicies: {
        get: {
            api: "SQLManagementClient",
            reliesOnService: ['resourceGroups', 'servers', 'databases'],
            reliesOnSubService: [undefined, 'sql', undefined],
            reliesOnCall: ['list', 'list', 'listByServer'],
            filterKey: ['resourceGroupName', 'serverName', 'databaseName'],
            filterValue: ['resourceGroupName', 'serverName', 'name'],
            arm: true
        }
    },
	vaults: {
        get: {
            api: "KeyVaultManagementClient",
            reliesOnService: ['resourceGroups','vaults'],
            reliesOnCall: ['list','listByResourceGroup'],
            filterKey: ['resourceGroupName','name'],
            filterValue: ['resourceGroupName','name'],
            arm: true
        }
    },
    transparentDataEncryptions: {
        get: {
            api: "SQLManagementClient",
            reliesOnService: ['resourceGroups', 'servers', 'databases'],
            reliesOnSubService: [undefined, 'sql', undefined],
            reliesOnCall: ['list', 'list', 'listByServer'],
            filterKey: ['resourceGroupName', 'serverName', 'databaseName'],
            filterValue: ['resourceGroupName', 'serverName', 'name'],
            arm: true
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

// Loop through all of the top-level collectors for each service
var processCall = function (AzureConfig, collection, settings, call, service, serviceCb) {
    // Initialize collection service and locations
    if (!collection[service]) collection[service] = {};

    var locations = helpers.locations(false)[service].locations ? helpers.locations(false)[service].locations : helpers.locations(false)[service];

    if (!call.manyApi) {
        async.eachOfLimit(call, 10, function (callObj, callKey, callCb) {
            if (!collection[service][callKey]) collection[service][callKey] = {};
            if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return callCb();

            executeCall(AzureConfig, collection, collection[service][callKey], service, callObj, callKey, locations, callCb);

        }, function () {
            serviceCb();
        });
    } else {
        async.eachOfLimit(call, 10, function (callInt, item, itemsCb) {
            var myEngine = item;
            async.eachOfLimit(callInt, 10, function(callObj, callKey, callCb) {
                if (settings.api_calls && settings.api_calls.indexOf(service + ':' + myEngine + ':' + callKey) === -1) return callCb();
                if (!collection[service][myEngine]) collection[service][myEngine] = {};
                if (!collection[service][myEngine][callKey]) collection[service][myEngine][callKey] = {};

                executeCall(AzureConfig, collection, collection[service][myEngine][callKey], service, callObj, callKey, locations, callCb);

            }, function () {
                itemsCb();
            })
        }, function () {
            serviceCb();
        });
    }
};

var executeCall = function(AzureConfig, collection, collectionObject, service, callObj, callKey, locations, executeCallCb){
    for (l in locations) {
        if (!collectionObject[locations[l]]) {
            collectionObject[locations[l]] = { data: [] };
        }
    }

    var LocalAzureConfig = JSON.parse(JSON.stringify(AzureConfig));
    LocalAzureConfig.service = service;

    var executor = new helpers.AzureExecutor(LocalAzureConfig);
    executor.run(collection, service, callObj, callKey, function (err, data) {
        errorHandling(err, data, collectionObject, locations);

        if (!data) {
            return executeCallCb();
        }

        var locationsInArray = [];
        for (var d = 0; d < data.length; d++) {
            if (data[d].location &&
                locations &&
                locations.length &&
                locations.length > 0) {
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

        if (locationsInArray &&
            locationsInArray.length > 0) {
            for (locationSelected in locationsInArray) {
                var dataToPush = data.filter((d) => {
                    return d.location == locationsInArray[locationSelected];
                });

                if (collectionObject[locationsInArray[locationSelected]] == undefined) {
                    collectionObject[locationsInArray[locationSelected]] = {};
                }

                collectionObject[locationsInArray[locationSelected]].data = dataToPush;
            }
        } else {
            if (data.length > 0) {
                collectionObject['unknown'] = {};
                collectionObject['unknown'].data = data;
            }
        }
        executeCallCb();
    });
};

// Loop through all of the top-level collectors for each service
var collect = function (AzureConfig, settings, callback) {
    var collection = {};

    AzureConfig.maxRetries = 5;
    AzureConfig.retryDelayOptions = { base: 300 };
    AzureConfig.location = AzureConfig.location ? AzureConfig.location : 'global';

    var settings = settings;

    async.eachOfLimit(calls, 10, function (call, service, serviceCbcall) {
        var service = service;
        if (!collection[service]) collection[service] = {};

        processCall(AzureConfig, collection, settings, call, service, function () {
            serviceCbcall();
        });
    }, function () {
        // Now loop through the follow up calls
        async.eachOfLimit(postcalls, 10, function (postCall, service, serviceCbpostCall) {
            var service = service;
            if (!collection[service]) collection[service] = {};

            processCall(AzureConfig, collection, settings, postCall, service, function () {
                serviceCbpostCall();
            });
        }, function () {
            // Now loop through the follow up calls
            async.eachOfLimit(finalcalls, 10, function (finalCall, service, serviceCbfinalCall) {
                var service = service;
                if (!collection[service]) collection[service] = {};

                processCall(AzureConfig, collection, settings, finalCall, service, function () {
                    serviceCbfinalCall();
                });

            }, function () {
                // Now loop through the follow up calls
                async.eachOfLimit(postfinalcalls, 10, function (postFinalCall, service, serviceCbpostFinalCall) {
                    var service = service;
                    if (!collection[service]) collection[service] = {};

                    processCall(AzureConfig, collection, settings, postFinalCall, service, function () {
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

function errorHandling(err, data, collectionObject, locations) {
    if ((err && err.length == undefined) == true || (err && err.length !== undefined && err.length > 0) == true) {
        for (l in locations) {
            if (err.body && err.body.message) {
                collectionObject[locations[l]].err = err.body.message;
            } else if (err.body && err.body.error && err.body.error.message) {
                collectionObject[locations[l]].err = err.body.error.message;
            } else if (data && data.length && data.length>0 && err.length && err.length>0) {
                var errorsReturned = '';
                for (e in err){
                    if (![404, 403, 400].includes(err[e].statusCode)){
                        errorsReturned += err[e].message + '; ';
                    }
                }
                if (errorsReturned.length) {
                    collectionObject[locations[l]].err = errorsReturned;
                }
            } else {
                collectionObject[locations[l]].err = "An error ocurred while retrieving service data";
            }
        }
    }
}

module.exports = collect;