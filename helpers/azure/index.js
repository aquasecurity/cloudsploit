var regLocations = require('./locations.js');
var govLocations = require('./locations_gov.js');

var async = require('async');
var util = require('util');

var msRestAzure = require('ms-rest-azure');
// Azure Resource Management
var ResourceManagementClient = require('azure-arm-resource').ResourceManagementClient;
var StorageManagementClient = require('azure-arm-storage');

// Azure Service Modules
var StorageServiceClient = require('azure-storage');

// Api Mapping
var mapAzureApis = {
    "ResourceManagementClient" : ResourceManagementClient,
    "StorageManagementClient" : StorageManagementClient,
	"StorageServiceClient" : StorageServiceClient
}

var locations = function(govcloud) {
	if (govcloud) return govLocations;
	return regLocations;
};

// Azure Executor
function AzureExecutor (AzureConfig, Service) {
    this.azureConfig = AzureConfig;
    this.azure = msRestAzure;

    this.client = {};
    this.auxClient = {};

    this.runarm = function(collection, callObj, callKey, callback){
        var AzureConfig = this.azureConfig;
		callObj.collection = collection;

        if(callObj.reliesOnService && callObj.reliesOnService.length){
                // ßconsole.log('ARM: Relies on multiple resource managers');
				this.azure.loginWithServicePrincipalSecret(AzureConfig.ApplicationID, AzureConfig.KeyValue, AzureConfig.DirectoryID, function (err, credentials) {
					if (err) return console.log(err);

					this.client = new mapAzureApis[callObj.api](credentials, AzureConfig.SubscriptionID);

					if (callObj.reliesOnAPI) {
						this.auxClient = new mapAzureApis[callObj.reliesOnAPI](credentials, AzureConfig.SubscriptionID);
					}

					// console.log('\n-->Listing ' + AzureConfig.service + ' ' + callKey + ' in the current subscription.');

					switch (callObj.reliesOnService.length){
                        case 1:
							// console.log('ARM: relies on 1');
							return this.client[AzureConfig.service][callKey](
								callObj.collection[callObj.reliesOnService[0]][callObj.reliesOnCall[0]][AzureConfig.location].data[0].name,
								function (err, result, request, response) {
									if (err) {
										return callback(err);
									}
									// console.log('\n' + util.inspect(result, {depth: null}));
									callback(null, result);
								});
                        case 2:
							// console.log('ARM: relies on 2');
							return this.client[AzureConfig.service][callKey](
									callObj.collection[callObj.reliesOnService[0]][callObj.reliesOnCall[0]][AzureConfig.location].data[0][callObj["filterKey"][0]],
									callObj.collection[callObj.reliesOnService[1]][callObj.reliesOnCall[1]][AzureConfig.location].data[0][callObj["filterKey"][1]],
									function (err, result, request, response) {
									if (err) {
										return callback(err);
									}
										// console.log('\n' + util.inspect(result, { depth: null }));
									callback(null, result);
							});
					}
				});
        } else {
			this.azure.loginWithServicePrincipalSecret(AzureConfig.ApplicationID, AzureConfig.KeyValue, AzureConfig.DirectoryID, function (err, credentials) {
				if (err) return console.log(err);
				this.client = new mapAzureApis[callObj.api](credentials, AzureConfig.SubscriptionID);
				if (callObj.reliesOnAPI) {
					this.auxClient = new mapAzureApis[callObj.reliesOnAPI](credentials, AzureConfig.SubscriptionID);
				}
				// console.log('\n-->Listing ' + AzureConfig.service + ' ' + callKey + ' in the current subscription.');
				return this.client[AzureConfig.service][callKey](AzureConfig.location, function (err, result, request, response) {
					if (err) {
						return callback(err);
					}

					var currentLocation = AzureConfig.location.replace(" ","").toLowerCase();
					var finalResult = [];
					for (r in result){
						if (result[r].location == currentLocation){
							finalResult.push(result[r]);
						}
					}

					// console.log('\n' + util.inspect(result, {depth: null}));
					callback(null, finalResult);
				});
			});
        }
    }

	this.runasm = function(collection, callObj, callKey, callback){
		var AzureConfig = this.azureConfig;
		callObj.collection = collection;

		if(callObj.reliesOnService && callObj.reliesOnService.length){
				// console.log('ASM: relies on multiple services');
				this.azure.loginWithServicePrincipalSecret(AzureConfig.ApplicationID, AzureConfig.KeyValue, AzureConfig.DirectoryID, function (err, credentials) {
					if (err) return console.log(err);

					switch (callObj.reliesOnService.length){
						case 1:
							// console.log('ASM: relies on 1');
							this.client = new mapAzureApis[callObj.api][AzureConfig.service](
								callObj.collection[callObj.reliesOnService[0]][callObj.reliesOnCall[0]][AzureConfig.location].data[0][callObj["filterKey"][0]]
							);
						case 2:
							// console.log('ASM: relies on 2');
							this.client = new mapAzureApis[callObj.api][AzureConfig.service](
								callObj.collection[callObj.reliesOnService[0]][callObj.reliesOnCall[0]][AzureConfig.location].data[0][callObj["filterKey"][0]],
								callObj.collection[callObj.reliesOnService[1]][callObj.reliesOnCall[1]][AzureConfig.location].data[callObj["filterKey"][1]][0][callObj["filterValue"][1]]
							);
					}

					return this.client[callKey](null, function (err, result, request, response) {
						if (err) {
							return callback(err);
						}
						// console.log('\n' + util.inspect(result, {depth: null}));
						callback(null, result);
					});

				});
		} else {
			// console.log('ASM: Direct Call (no params)');

			this.client = new mapAzureApis[callObj.api][AzureConfig.service]();

			return this.client[callKey](null, function (err, result, request, response) {
				if (err) {
					return callback(err);
				}
				// console.log('\n' + util.inspect(result, {depth: null}));
				callback(null, result);
			});
		}
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
	normalizePolicyDocument: require('./functions.js').normalizePolicyDocument,

    MAX_LOCATIONS_AT_A_TIME: 6
};