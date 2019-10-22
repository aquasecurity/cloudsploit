var shared = require(__dirname + '/../shared.js');
var functions = require('./functions.js');
var regLocations = require('./locations.js');
var govLocations = require('./locations_gov.js');

var msRestAzure                 = require('ms-rest-azure');

// Azure Resource Management
var ComputeManagementClient     = require('azure-arm-compute');
var KeyVaultManagementClient    = require('azure-arm-keyvault');
var MonitorManagementClient     = require('azure-arm-monitor');
var NetworkManagementClient     = require('azure-arm-network');
var PolicyClient                = require('azure-arm-resource').PolicyClient;
var ResourceManagementClient    = require('azure-arm-resource').ResourceManagementClient;
var SQLManagementClient         = require('azure-arm-sql');
var StorageManagementClient     = require('azure-arm-storage');
var WebSiteManagementClient     = require('azure-arm-website');
var ContainerServiceClient      =  require('azure-arm-containerservice');
var CdnManagementClient         = require('azure-arm-cdn');
var ManagementLockClient        = require('azure-arm-resource').ManagementLockClient;
var MySQLManagementClient       = require('azure-arm-mysql');
var SecurityCenterClient        = require('azure-arm-security');
var SubscriptionClient          = require('azure-arm-resource').SubscriptionClient;
var PostgresClient              = require('azure-arm-postgresql');

// Azure Service Modules
var KeyVaultClient              = require('azure-keyvault');
var StorageServiceClient        = require('azure-storage');

// Api Mapping
var mapAzureApis = {
    "ComputeManagementClient"   : ComputeManagementClient,
    "KeyVaultClient"            : KeyVaultClient,
    "KeyVaultManagementClient"  : KeyVaultManagementClient,
    "MonitorManagementClient"   : MonitorManagementClient,
    "NetworkManagementClient"   : NetworkManagementClient,
    "PolicyClient"              : PolicyClient,
    "ResourceManagementClient"  : ResourceManagementClient,
    "SQLManagementClient"       : SQLManagementClient,
    "StorageManagementClient"   : StorageManagementClient,
    "StorageServiceClient"      : StorageServiceClient,
    "WebSiteManagementClient"   : WebSiteManagementClient,
    "ContainerServiceClient"    : ContainerServiceClient, 
    "CdnManagementClient"       : CdnManagementClient,
    "ManagementLockClient"      : ManagementLockClient,
    "MySQLManagementClient"     : MySQLManagementClient,
    "SecurityCenterClient"      : SecurityCenterClient,
    "SubscriptionClient"        : SubscriptionClient,
    "PostgresClient"            : PostgresClient
}

const UNKNOWN_LOCATION = "unknown";

var locations = function(govcloud) {
    if (govcloud) return govLocations;
    return regLocations;
};

// Azure Executor
class AzureExecutor {
    constructor (AzureConfig) {
        this.azure = msRestAzure;
        this.azureConfig = AzureConfig;
        this.collection = {};
    }

    run (collection, azureService, callObj, callKey, callback) {
        this.collection = collection;
        var self = this;

        this.azure.loginWithServicePrincipalSecret(this.azureConfig.ApplicationID, this.azureConfig.KeyValue, this.azureConfig.DirectoryID, function (err, credentials) {
            if (err){
                if (err.message &&
                    err.message.indexOf("unauthorized_client")>0) {
                    err.body = {};
                    err.body.message = "Unauthorized Client: Failed to acquire token for application with the provided secret. Unable to authenticate into Azure Account.";
                }
                return callback(err, null);
            }
            // console.log('Azure :::... New Session');

            if (callObj.reliesOnService) {
                self.azureMany(credentials, callObj, callKey, callback);
            } else {
                var parameters = {};

                for (var filter in callObj.filterKey) {
                    if (callObj.filterLiteral && callObj.filterLiteral[filter]) {
                        parameters[callObj.filterKey[filter]] = callObj.filterValue[filter];
                    } else {
                        parameters[callObj.filterKey[filter]] = AzureConfig[callObj.filterValue[filter]];
                    }
                }

                var api = new ApiCall(self.azureConfig, credentials, callObj, callKey, null, null);
                api.execute().then(function (results) {
                    if (results && results.error==true){
                        var err=results;
                        callback(err, null);
                    } else if (results && results.error==false){
                        results.forEach((result) => {
                          if (result.locations) {
                            result.location = result.locations[0];
                          }
                        });

                        callback(null, results);
                    }
                });
            }

            // console.log('Azure :::... Session Closed');
        });
    }

    azureMany(credentials, callObj, callKey, callback) {
        var serviceCollection = {};
        var serviceArray = [];
        var entryArray = [];

        var self = this;
        self.aggregatedErrors=[];
        self.aggregatedResults=[];

        function aggregateServices(services, fn, context) {
            return services.reduce(function (promise, service) {
                return promise.then(function () {
                    return fn(service, context);
                });
            }, Promise.resolve());
        }

        function aggregateEntries(entries, fn, context) {
            // self.aggregatedErrors=[];
            // self.aggregatedResults=[];
            return entries.reduce(function (promise, entry) {
                return promise.then(function () {
                    return fn(entry, context);
                });
            }, Promise.resolve());
        }

        function addProperties(result,service) {
            if (result.id == undefined) result.id = service.id;
            if (result.location == undefined) result.location = service.location;
            
            //Validate where this property is used
            //Remove if not used  
            if (result.storageAccount == undefined) {
                result.storageAccount = {};
                result.storageAccount.name = service.name;
            }
            return result;
        }

        function executeOne(service, context) {
            return new Promise((resolve, reject) => {
                process.nextTick(() => {
                    service.api = new ApiCall(self.azureConfig, credentials, callObj, callKey, service.location, service.parameters);
                    service.api.execute().then(function (results) {
                        if (results==undefined){
                            results = {};
                            results.error=true;
                            results.message="Err: No service data returned";
                            context.aggregatedErrors.push(results);
                        }

                        if (results && results.error==true) {
                            context.aggregatedErrors.push(results);
                        }

                        if (results && results.error==false) {
                            if (Array.isArray(results)) {
                                results.forEach((r) => {
                                    addProperties(r,service)
                                });
                                context.aggregatedResults = context.aggregatedResults.concat(results);
                            } else {
                                context.aggregatedResults.push(addProperties(results,service));
                            }
                        }
                        resolve();
                    });
                })
            });
        }

        function loadServiceCollection() {
            if (callObj.reliesOnService.length &&
                callObj.reliesOnService.length>1){
                for (var reliedService in callObj.reliesOnService) {
                    if (callObj.reliesOnService[reliedService] !== 'resourceGroups' &&
                        (!callObj.reliesOnSubService ||
                            !callObj.reliesOnSubService[reliedService])) {
                        if (!serviceCollection[callObj.reliesOnService[reliedService]]) {
                            serviceCollection[callObj.reliesOnService[reliedService]] = self.collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]];
                        }
                    } else if (callObj.reliesOnService[reliedService] !== 'resourceGroups' &&
                                callObj.reliesOnSubService &&
                                callObj.reliesOnSubService[reliedService]) {
                        if (!serviceCollection[callObj.reliesOnService[reliedService]]) {
                            serviceCollection[callObj.reliesOnService[reliedService]] = self.collection[callObj.reliesOnService[reliedService]][callObj.reliesOnSubService[reliedService]][callObj.reliesOnCall[reliedService]];
                        }
                    }
                }
            } else {
                serviceCollection[callObj.reliesOnService[0]] = self.collection[callObj.reliesOnService[0]][callObj.reliesOnCall[0]];
            }

            self.serviceCollection = serviceCollection;
        }

        function loadParameters() {
            for (var serviceName in serviceCollection) {
                var service = serviceCollection[serviceName];

                if (callObj.reliesOnService &&
                    callObj.reliesOnService.length &&
                    callObj.reliesOnService.length >= 3 &&
                    callObj.reliesOnService[2] != serviceName) {
                    continue;
                }

                for (var location in service) {
                    if (location==UNKNOWN_LOCATION) continue;
                    var workOnServicesAtLocation = service[location].data;
                    // Build Parameters
                    for (var locat in workOnServicesAtLocation) {
                        var serviceAtLocation = workOnServicesAtLocation[locat];
                        serviceAtLocation.parameters = {};

                        serviceArray.push(serviceAtLocation);

                        if (serviceAtLocation.id &&
                            ( serviceAtLocation.id.indexOf('/resourceGroups/') > -1 ||
                                serviceAtLocation.id.indexOf('/resourcegroups/') > -1 ) &&
                            serviceName!=='resourceGroups') {

                            let resourceGroupInitIndex = serviceAtLocation.id.indexOf('/resourceGroups/') > -1 ? serviceAtLocation.id.indexOf('/resourceGroups/') : serviceAtLocation.id.indexOf('/resourcegroups/');
                            var resourceGroupIndex = resourceGroupInitIndex + '/resourceGroups/'.length;
                            var resourceGroupEndIndex = serviceAtLocation.id.indexOf('/', resourceGroupIndex);
                            var resourceGroupName = serviceAtLocation.id.substring(resourceGroupIndex, resourceGroupEndIndex);
                            var resourceGroupId = serviceAtLocation.id.substring(0, resourceGroupEndIndex);

                            serviceAtLocation.resourceGroupName = resourceGroupName;
                            serviceAtLocation.resourceGroupId = resourceGroupId;

                            if (serviceAtLocation.id &&
                                ( serviceAtLocation.id.indexOf('/profiles/') > -1) &&
                                serviceName!=='profiles') {

                                let profileInitIndex = serviceAtLocation.id.indexOf('/profiles/');
                                var profileIndex = profileInitIndex + '/profiles/'.length;
                                var profileEndIndex = serviceAtLocation.id.indexOf('/', profileIndex);
                                var profileName = serviceAtLocation.id.substring(profileIndex, profileEndIndex);
                                serviceAtLocation.profileName = profileName;
                            }

                        } else if (serviceName=='resourceGroups'){
                            var resourceGroupName = serviceAtLocation.name;
                            var resourceGroupId = serviceAtLocation.id;
                            serviceAtLocation.resourceGroupName = resourceGroupName;
                            serviceAtLocation.resourceGroupId = resourceGroupId;
                        }

                        for (var filter in callObj.filterKey) {
                            if (callObj.filterLiteral && callObj.filterLiteral[filter]) {
                                serviceAtLocation.parameters[callObj.filterKey[filter]] = callObj.filterValue[filter];
                            } else if (callObj.filterConfig && callObj.filterConfig[filter]) {
                                serviceAtLocation.parameters[callObj.filterKey[filter]] = self.azureConfig[callObj.filterValue[filter]];
                            } else if (callObj.filterListKeys && callObj.filterListKeys[filter]) {
                                if (self.collection.storageAccounts.listKeys[location]) {
                                    var keyList = self.collection.storageAccounts.listKeys[location].data.filter((d) => {
                                        return d.storageAccount.name == serviceAtLocation.parameters.name;
                                    });
                                    if (keyList && keyList.length > 0) {
                                        serviceAtLocation.parameters[callObj.filterKey[filter]] = keyList[0].keys[0].value;
                                    }
                                }
                            } else if (callObj.filterKey[filter] == 'databaseName'
                                    && serviceAtLocation.type == 'Microsoft.Sql/servers/databases'
                                    && callObj.filterKey.find(key => key == 'serverName')) {

                                    var idSplits = serviceAtLocation.id.split('/');
                                    var serverName = idSplits[idSplits.length - 3];

                                    serviceAtLocation.parameters['serverName'] = serverName;
                                    serviceAtLocation.parameters['databaseName'] = serviceAtLocation.name;
                            } else if (serviceAtLocation.entries) {
                                if (callObj.reliesOnService[filter]=='storageAccounts' && callObj.filterKey[filter]=='name' ) {
                                    serviceAtLocation.parameters[callObj.filterKey[filter]] = serviceAtLocation.storageAccount.name;
                                }
                            } else {
                                serviceAtLocation.parameters[callObj.filterKey[filter]] = serviceAtLocation[callObj.filterValue[filter]];
                            }
                        }
                    }
                }
            }
        }

        function loadEntryArray() {
            var entryServices = [];
            for (var s = 0; s < serviceArray.length; s++) {
                var service = serviceArray[s];
                var entries = serviceArray[s].entries;
                if (entries.length == 0) {
                    continue;
                }
                for (var i = 0; i < entries.length; i++) {
                    var parameter = (entries[i][callObj["filterKey"][2]] ? entries[i][callObj["filterKey"][2]] : entries[i]);
                    service.parameters[callObj["entryKey"][2]] = parameter;
                    service.entry = entries[i];
                    entryArray.push(service);
                }
            }
        }

        // Load services for which results will be aggregated
        loadServiceCollection();

        // Load parameters for services loaded
        loadParameters();

        // If entry dependent, create entryArray and
        // aggregate entries results
        if (callObj.entryKey) {
            loadEntryArray();

            aggregateEntries(entryArray, executeOne, self).then(() => {
                callback(self.aggregatedErrors, self.aggregatedResults);
            });
        } else {
            aggregateServices(serviceArray, executeOne, self).then(() => {
                callback(self.aggregatedErrors, self.aggregatedResults);
            });
        }
    }
}

class ApiCall {
    constructor (AzureConfig, credentials, callObj, callKey, location, parameters) {
        this.AzureConfig = AzureConfig;
        this.credentials = credentials;
        this.callObj = callObj;
        this.callKey = callKey;
        this.location = location;
        this.parameters = parameters;
        this.options = {};
        this.client = {};
    }

    execute () {
        var self = this;

        return new Promise(function(resolve, reject) {

            function universalResolve(err, results, request, response){
                if (err){
                    if (err.response &&
                        err.response.statusCode &&
                        err.response.statusCode==404){
                        err.message = "Record Not Found";
                    }
                    err.error=true;
                    resolve(err);
                }

                if (results){
                    results.error=false;
                    resolve(results);
                }
            }

            if (self.callObj.arm) {
                if (self.callObj.module) {
                    self.client = new mapAzureApis[self.callObj.api][self.AzureConfig.service](self.credentials);
                } else if (self.callObj.ascLoc) {
                    self.client = new mapAzureApis[self.callObj.api](self.credentials, self.AzureConfig.SubscriptionID, self.AzureConfig.location);
                } else if (self.callObj.noSubscription) {
                    self.client = new mapAzureApis[self.callObj.api](self.credentials);
                }else {
                    self.client = new mapAzureApis[self.callObj.api](self.credentials, self.AzureConfig.SubscriptionID);
                }

                if (!self.callObj.module && self.parameters) {
                    switch (self.callObj.filterKey.length) {
                        case 1:
                            self.client[self.AzureConfig.service][self.callKey](self.parameters[self.callObj.filterKey[0]], self.options, function(err, results, request, response) {
                                universalResolve(err, results, request, response);
                            });
                            break;
                        case 2:
                            self.client[self.AzureConfig.service][self.callKey](self.parameters[self.callObj.filterKey[0]], self.parameters[self.callObj.filterKey[1]], self.options, function(err, results, request, response) {
                                universalResolve(err, results, request, response);
                            });
                            break;
                        case 3:
                            self.client[self.AzureConfig.service][self.callKey](self.parameters[self.callObj.filterKey[0]], self.parameters[self.callObj.filterKey[1]], self.parameters[self.callObj.filterKey[2]], self.options, function(err, results, request, response) {
                                universalResolve(err, results, request, response);
                            });
                            break;
                    }
                } else if (self.callObj.module && self.parameters) {
                    switch (self.callObj.filterKey.length) {
                        case 1:
                            self.client[self.callKey](self.parameters[self.callObj.filterKey[0]], function(err, results, request, response) {
                                universalResolve(err, results, request, response);
                            });
                            break;
                        case 2:
                            self.client[self.callKey](self.parameters[self.callObj.filterKey[0]], self.parameters[self.callObj.filterKey[1]], function(err, results, request, response) {
                                universalResolve(err, results, request, response);
                            });
                            break;
                        case 3:
                            self.client[self.callKey](self.parameters[self.callObj.filterKey[0]], self.parameters[self.callObj.filterKey[1]], self.parameters[self.callObj.filterKey[2]], function(err, results, request, response) {
                                universalResolve(err, results, request, response);
                            });
                            break;
                    }
                } else if (self.AzureConfig.service == "subscriptions") {
                    return self.client[self.AzureConfig.service][self.callKey](self.AzureConfig.SubscriptionID,self.AzureConfig, function(err, results, request, response) {
                        universalResolve(err, results, request, response);
                    });
                } else {
                    return self.client[self.AzureConfig.service][self.callKey](self.AzureConfig, function(err, results, request, response) {
                        universalResolve(err, results, request, response);
                    });
                }
            } else {
                if(!self.callObj.keyVault) {
                    if (self.parameters) {
                        switch (self.callObj.filterKey.length) {
                            case 1:
                                self.client = new mapAzureApis[self.callObj.api][self.AzureConfig.service](self.parameters[self.callObj.filterKey[0]]);
                                return self.client[self.callKey](null, function(err, results, request, response) {
                                    universalResolve(err, results, request, response);
                                });
                                break;
                            case 2:
                                if (self.parameters[self.callObj.filterKey[0]] && self.parameters[self.callObj.filterKey[1]]) {
                                    self.client = new mapAzureApis[self.callObj.api][self.AzureConfig.service](self.parameters[self.callObj.filterKey[0]], self.parameters[self.callObj.filterKey[1]]);
                                    self.client[self.callKey](null, self.options, function(err, results, request, response) {
                                        universalResolve(err, results, request, response);
                                    });
                                } else {
                                    universalResolve({"message":"Error: Parameters not supplied"} );
                                }
                                break;
                            case 3:
                                if (self.parameters[self.callObj.filterKey[0]] && self.parameters[self.callObj.filterKey[1]] && self.parameters[self.callObj.entryKey[2]]) {
                                    self.client = new mapAzureApis[self.callObj.api][self.AzureConfig.service](self.parameters[self.callObj.filterKey[0]], self.parameters[self.callObj.filterKey[1]]);
                                    self.client[self.callKey](self.parameters[self.callObj.entryKey[2]], self.options, function(err, results, request, response) {
                                        universalResolve(err, results, request, response);
                                    });
                                } else {
                                    universalResolve({"message":"Error: Parameters not supplied"} );
                                }
                            default:
                                break;
                        }
                    }
                } else {
                    if (self.parameters) {
                        self.client = new mapAzureApis[self.callObj.api][self.AzureConfig.service](self.credentials);
                        return self.client[self.callKey](`https://${self.parameters[self.callObj.filterKey[0]]}.vault.azure.net`, function(err, results, request, response) {
                            universalResolve(err, results, request, response);
                        });
                    };
                };
            };
        });
    }
}

var helpers = {
    locations: locations,
    AzureExecutor: AzureExecutor
};

for (s in shared) helpers[s] = shared[s];
for (f in functions) helpers[f] = functions[f];

module.exports = helpers;
