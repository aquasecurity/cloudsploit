var regLocations = require('./locations.js');
var govLocations = require('./locations_gov.js');

var msRestAzure                 = require('ms-rest-azure');

// Azure Resource Management
var ComputeManagementClient     = require('azure-arm-compute');
var KeyVaultMangementClient     = require('azure-arm-keyvault');
var MonitorManagementClient     = require('azure-arm-monitor');
var NetworkManagementClient     = require('azure-arm-network');
var PolicyClient                = require('azure-arm-resource').PolicyClient;
var ResourceManagementClient    = require('azure-arm-resource').ResourceManagementClient;
var SQLManagementClient         = require('azure-arm-sql');
var StorageManagementClient     = require('azure-arm-storage');
var WebSiteManagementClient     = require('azure-arm-website');

// Azure Service Modules
var KeyVaultClient              = require('azure-keyvault');
var StorageServiceClient        = require('azure-storage');

// Api Mapping
var mapAzureApis = {
	"ComputeManagementClient"   : ComputeManagementClient,
	"KeyVaultClient"            : KeyVaultClient,
	"KeyVaultMangementClient"   : KeyVaultMangementClient,
	"MonitorManagementClient"   : MonitorManagementClient,
	"NetworkManagementClient"   : NetworkManagementClient,
	"PolicyClient"              : PolicyClient,
	"ResourceManagementClient"  : ResourceManagementClient,
	"SQLManagementClient"       : SQLManagementClient,
	"StorageManagementClient"   : StorageManagementClient,
	"StorageServiceClient"      : StorageServiceClient,
	"WebSiteManagementClient"   : WebSiteManagementClient,
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
			if (err) return console.log(err);
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
					if (callObj.reliesOnService[reliedService] !== 'resourceGroups') {
						if (!serviceCollection[callObj.reliesOnService[reliedService]]) {
							serviceCollection[callObj.reliesOnService[reliedService]] = self.collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]];
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

				for (var location in service) {
					if (location==UNKNOWN_LOCATION) continue;
					var workOnServicesAtLocation = service[location].data;
					// Build Parameters
					for (var locat in workOnServicesAtLocation) {
						var serviceAtLocation = workOnServicesAtLocation[locat];
						serviceAtLocation.parameters = {};

						serviceArray.push(serviceAtLocation);

                        if (serviceAtLocation.id && ( serviceAtLocation.id.indexOf('/resourceGroups/') > -1 || serviceAtLocation.id.indexOf('/resourcegroups/') > -1 ) && serviceName!=='resourceGroups') {
                            let resourceGroupInitIndex = serviceAtLocation.id.indexOf('/resourceGroups/') > -1 ? serviceAtLocation.id.indexOf('/resourceGroups/') : serviceAtLocation.id.indexOf('/resourcegroups/');
                            var resourceGroupIndex = resourceGroupInitIndex + '/resourceGroups/'.length;
							var resourceGroupEndIndex = serviceAtLocation.id.indexOf('/', resourceGroupIndex);
							var resourceGroupName = serviceAtLocation.id.substring(resourceGroupIndex, resourceGroupEndIndex);
							var resourceGroupId = serviceAtLocation.id.substring(0, resourceGroupEndIndex);
							serviceAtLocation.resourceGroupName = resourceGroupName;
							serviceAtLocation.resourceGroupId = resourceGroupId;
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
							} else {
                                // databaseName handling
                                if (callObj.filterKey[filter] == 'databaseName'
                                    && serviceAtLocation.type == 'Microsoft.Sql/servers/databases'
                                    && callObj.filterKey.find(key => key == 'serverName')) {

                                    var idSplits = serviceAtLocation.id.split('/');
                                    var serverName = idSplits[idSplits.length - 3];

                                    serviceAtLocation.parameters['serverName'] = serverName;
                                    serviceAtLocation.parameters['databaseName'] = serviceAtLocation.name;
                                } else {
								serviceAtLocation.parameters[callObj.filterKey[filter]] = serviceAtLocation[callObj.filterValue[filter]];
							}
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
				entryServices = callObj.collection[callObj.reliesOnService[2]][callObj.reliesOnCall[2]][service.location].data;
				for (var e = 0; e < entryServices.length; e++) {
					var entries = entryServices[e].entries;
					if (entries.length == 0) {
						continue;
					}
					for (var i = 0; i < entries.length; i++) {
						var parameter = (entries[i][callObj["filterKey"][2]] ? entries[i][callObj["filterKey"][2]] : entries[i]);

						service.parameters[callObj["entryKey"][2]] = parameter;
						service.entry = entries[i];
						entryArray.push(service);
						//TO DO: Limit queries per entry based on the storageAccount
					}
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
				} else {
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
				} else {
					return self.client[self.AzureConfig.service][self.callKey](self.AzureConfig, function(err, results, request, response) {
						universalResolve(err, results, request, response);
					});
				}
			} else {
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
			}
		});
	}
}

module.exports = {
	locations: locations,
	AzureExecutor: AzureExecutor,
	functions: require('./functions.js'),
	addResult: require('./functions.js').addResult,
	addSource: require('./functions.js').addSource,
	addError: require('./functions.js').addError,
	isCustom: require('./functions.js').isCustom,
	cidrSize: require('./functions.js').cidrSize,
	findOpenPorts: require('./functions.js').findOpenPorts,
	normalizePolicyDocument: require('./functions.js').normalizePolicyDocument
};