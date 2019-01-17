"use strict";

/*********************
 Collector - The collector will query GitHub APIs for the information required
 to run the CloudSploit scans. This data will be returned in the callback
 as a JSON object.
 *********************/

var async = require('async');
var util = require('util');

var collectors = require(__dirname + '/../../collectors/github');

var calls = {
	apps: {
		listInstallationsForAuthenticatedUser: {
			params: {
				per_page: 100
			}
		}
	},
	orgs: {
		listForAuthenticatedUser: {
			params: {
				per_page: 100
			}
		}
	},
	users: {
		listPublicKeys: {
			params: {
				per_page: 100
			}
		},
		listGpgKeys: {
			params: {
				per_page: 100
			}
		},
		getAuthenticated: {
			params: {}
		},
		listEmails: {
			params: {
				per_page: 100
			}
		}
	}
};

var collection = {};

// Loop through all of the top-level collectors for each service
var collect = function (GitHubConfig, settings, callback) {
	var octokit = require('@octokit/rest')({
		baseUrl: GitHubConfig.url
	});
	octokit.authenticate({
		type: 'token',
		token: GitHubConfig.token
	});

	async.eachOfLimit(calls, 10, function(call, service, serviceCb){
		var serviceLower = service.toLowerCase();
		if (!collection[serviceLower]) collection[serviceLower] = {};

		// Loop through each of the service's functions
		async.eachOfLimit(call, 10, function (callObj, callKey, callCb) {
			if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return callCb();
			if (!collection[serviceLower][callKey]) collection[serviceLower][callKey] = {};

			var params = callObj.params || {};

			var finish = function() {
				if (callObj.rateLimit) {
					setTimeout(function () {
						callCb();
					}, callObj.rateLimit);
				} else {
					callCb();
				}
			};

			if (callObj.override) {
				collectors[serviceLower][callKey](octokit, collection, function () {
					finish();
				});
			} else {
				octokit[service][callKey](params).then(function(results){
					if (results && results.data) collection[serviceLower][callKey].data = results.data;
					finish();
				}, function(err){
					if (err) collection[serviceLower][callKey].err = err;
					finish();
				});
			}
		}, function(){
			serviceCb();
		});
	}, function(){
		callback(null, collection);
	});
	
  //   async.eachOfLimit(calls, 10, function (call, service, serviceCb) {
		

  //       // Loop through each of the service's functions
  //       async.eachOfLimit(call, 10, function (callObj, callKey, callCb) {
  //           if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return callCb();
  //           if (!collection[serviceLower][callKey]) collection[serviceLower][callKey] = {};

  //           async.eachLimit(locations[serviceLower], helpers.MAX_LOCATIONS_AT_A_TIME, function (location, locationCb) {
  //               if (settings.skip_locations &&
  //                   settings.skip_locations.indexOf(location) > -1 &&
  //                   globalServices.indexOf(service) === -1) return locationCb();
  //               if (!collection[serviceLower][callKey][location]) collection[serviceLower][callKey][location] = {};

  //               var LocalAzureConfig = JSON.parse(JSON.stringify(AzureConfig));
  //               LocalAzureConfig.location = location;
  //               LocalAzureConfig.service = service;

  //               if (callObj.override) {
  //                   collectors[serviceLower][callKey](LocalAWSConfig, collection, function () {
  //                       if (callObj.rateLimit) {
  //                           setTimeout(function () {
  //                               locationCb();
  //                           }, callObj.rateLimit);
  //                       } else {
  //                           locationCb();
  //                       }
  //                   });
  //               } else {
  //                   var executor = new helpers.AzureExecutor(LocalAzureConfig);
  //                   executor.runarm(collection, callObj, callKey, function(err, data){
  //                       if (err) {
  //                           collection[serviceLower][callKey][location].err = err;
  //                       }

  //                       if (!data) return locationCb();

  //                       collection[serviceLower][callKey][location].data = data;

  //                       if (callObj.rateLimit) {
  //                           setTimeout(function(){
  //                               locationCb();
  //                           }, callObj.rateLimit);
  //                       } else {
  //                           locationCb();
  //                       }
  //                   });
  //               }
  //           }, function () {
  //               callCb();
  //           });
  //       }, function () {
  //           serviceCb();
  //       });
  //   }, function () {
  //       // Now loop through the follow up calls
  //       async.eachSeries(postcalls, function (postcallObj, postcallCb) {
  //           async.eachOfLimit(postcallObj, 10, function (serviceObj, service, serviceCb) {
  //               var serviceLower = service.toLowerCase();
  //               if (!collection[serviceLower]) collection[serviceLower] = {};

  //               async.eachOfLimit(serviceObj, 1, function (callObj, callKey, callCb) {
  //                   if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return callCb();
  //                   if (!collection[serviceLower][callKey]) collection[serviceLower][callKey] = {};

  //                   async.eachLimit(locations[serviceLower], helpers.MAX_LOCATIONS_AT_A_TIME, function (location, locationCb) {
  //                       if (settings.skip_locations &&
  //                           settings.skip_locations.indexOf(location) > -1 &&
  //                           globalServices.indexOf(service) === -1) return locationCb();
  //                       if (!collection[serviceLower][callKey][location]) collection[serviceLower][callKey][location] = {};

		// 				if (callObj.reliesOnService.length) {
		// 					// Ensure multiple pre-requisites are met
  //                           for (reliedService in callObj.reliesOnService){
		// 						if (callObj.reliesOnService[reliedService] && !collection[callObj.reliesOnService[reliedService].toLowerCase()]) return locationCb();

		// 						if (callObj.reliesOnCall[reliedService] &&
		// 							(!collection[callObj.reliesOnService[reliedService].toLowerCase()] ||
		// 							!collection[callObj.reliesOnService[reliedService].toLowerCase()][callObj.reliesOnCall[reliedService]] ||
		// 							!collection[callObj.reliesOnService[reliedService].toLowerCase()][callObj.reliesOnCall[reliedService]][location] ||
		// 							!collection[callObj.reliesOnService[reliedService].toLowerCase()][callObj.reliesOnCall[reliedService]][location].data ||
		// 							!collection[callObj.reliesOnService[reliedService].toLowerCase()][callObj.reliesOnCall[reliedService]][location].data.length)) return locationCb();
  //                           }
		// 				} else {
  //                           // Ensure pre-requisites are met
		// 					if (callObj.reliesOnService && !collection[callObj.reliesOnService.toLowerCase()]) return locationCb();

		// 					if (callObj.reliesOnCall &&
		// 						(!collection[callObj.reliesOnService.toLowerCase()] ||
		// 						!collection[callObj.reliesOnService.toLowerCase()][callObj.reliesOnCall] ||
		// 						!collection[callObj.reliesOnService.toLowerCase()][callObj.reliesOnCall][location] ||
		// 						!collection[callObj.reliesOnService.toLowerCase()][callObj.reliesOnCall][location].data ||
		// 						!collection[callObj.reliesOnService.toLowerCase()][callObj.reliesOnCall][location].data.length)) return locationCb();
		// 				}

  //                       var LocalAzureConfig = JSON.parse(JSON.stringify(AzureConfig));
  //                       LocalAzureConfig.location = location;
  //                       LocalAzureConfig.service = service;

  //                       if (callObj.deletelocation) {
  //                           //delete LocalAWSConfig.location;
  //                           LocalAzureConfig.location = settings.govcloud ? 'us-gov-west-1' : 'us-east-1';
  //                       } else {
  //                           LocalAzureConfig.location = location;
  //                       }
  //                       if (callObj.signatureVersion) LocalAzureConfig.signatureVersion = callObj.signatureVersion;

  //                       if (callObj.override) {
  //                           collectors[serviceLower][callKey](LocalAzureConfig, collection, function () {
  //                               if (callObj.rateLimit) {
  //                                   setTimeout(function () {
  //                                       locationCb();
  //                                   }, callObj.rateLimit);
  //                               } else {
  //                                   locationCb();
  //                               }
  //                           });
  //                       } else {
  //                           var executor = new helpers.AzureExecutor(LocalAzureConfig);
  //                           executor.runarm(collection, callObj, callKey, function(err, data){
  //                               if (err) {
  //                                   collection[serviceLower][callKey][location].err = err;
  //                               }

  //                               if (!data) return locationCb();

  //                               collection[serviceLower][callKey][location].data = data;

  //                               if (callObj.rateLimit) {
  //                                   setTimeout(function(){
  //                                       locationCb();
  //                                   }, callObj.rateLimit);
  //                               } else {
  //                                   locationCb();
  //                               }
  //                           });
  //                       }
  //                   }, function () {
  //                       callCb();
  //                   });
  //               }, function () {
  //                   serviceCb();
  //               });
  //           }, function () {
  //               postcallCb();
  //           });
  //       }, function () {
		// 	// Now loop through the final calls
		// 	async.eachSeries(finalcalls, function (finalcallObj, finalcallCb) {
		// 		async.eachOfLimit(finalcallObj, 10, function (serviceObj, service, serviceCb) {
		// 			var serviceLower = service.toLowerCase();
		// 			if (!collection[serviceLower]) collection[serviceLower] = {};

		// 			async.eachOfLimit(serviceObj, 1, function (callObj, callKey, callCb) {
		// 				if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return callCb();
		// 				if (!collection[serviceLower][callKey]) collection[serviceLower][callKey] = {};

		// 				async.eachLimit(locations[serviceLower], helpers.MAX_LOCATIONS_AT_A_TIME, function (location, locationCb) {
		// 					if (settings.skip_locations &&
		// 						settings.skip_locations.indexOf(location) > -1 &&
		// 						globalServices.indexOf(service) === -1) return locationCb();
		// 					if (!collection[serviceLower][callKey][location]) collection[serviceLower][callKey][location] = {};

		// 					if (callObj.reliesOnService.length) {
		// 						// Ensure multiple pre-requisites are met
		// 						for (reliedService in callObj.reliesOnService){
		// 							if (callObj.reliesOnService[reliedService] && !collection[callObj.reliesOnService[reliedService].toLowerCase()]) return locationCb();

		// 							if (callObj.reliesOnCall[reliedService] &&
		// 								(!collection[callObj.reliesOnService[reliedService].toLowerCase()] ||
		// 								!collection[callObj.reliesOnService[reliedService].toLowerCase()][callObj.reliesOnCall[reliedService]] ||
		// 								!collection[callObj.reliesOnService[reliedService].toLowerCase()][callObj.reliesOnCall[reliedService]][location] ||
		// 								!collection[callObj.reliesOnService[reliedService].toLowerCase()][callObj.reliesOnCall[reliedService]][location].data )) return locationCb();
		// 						}
		// 					} else {
		// 						// Ensure pre-requisites are met
		// 						if (callObj.reliesOnService && !collection[callObj.reliesOnService.toLowerCase()]) return locationCb();

		// 						if (callObj.reliesOnCall &&
		// 							(!collection[callObj.reliesOnService.toLowerCase()] ||
		// 							!collection[callObj.reliesOnService.toLowerCase()][callObj.reliesOnCall] ||
		// 							!collection[callObj.reliesOnService.toLowerCase()][callObj.reliesOnCall][location] ||
		// 							!collection[callObj.reliesOnService.toLowerCase()][callObj.reliesOnCall][location].data )) return locationCb();
		// 					}

		// 					var LocalAzureConfig = JSON.parse(JSON.stringify(AzureConfig));
		// 					LocalAzureConfig.location = location;
		// 					LocalAzureConfig.service = service;

		// 					if (callObj.deletelocation) {
		// 						//delete LocalAWSConfig.location;
		// 						LocalAzureConfig.location = settings.govcloud ? 'us-gov-west-1' : 'us-east-1';
		// 					} else {
		// 						LocalAzureConfig.location = location;
		// 					}
		// 					if (callObj.signatureVersion) LocalAzureConfig.signatureVersion = callObj.signatureVersion;

		// 					if (callObj.override) {
		// 						collectors[serviceLower][callKey](LocalAzureConfig, collection, function () {
		// 							if (callObj.rateLimit) {
		// 								setTimeout(function () {
		// 									locationCb();
		// 								}, callObj.rateLimit);
		// 							} else {
		// 								locationCb();
		// 							}
		// 						});
		// 					} else {
		// 						var executor = new helpers.AzureExecutor(LocalAzureConfig);
		// 						if (callObj.arm){
		// 							executor.runarm(collection, callObj, callKey, function(err, data){
		// 								if (err) {
		// 									collection[serviceLower][callKey][location].err = err;
		// 								}

		// 								if (!data) return locationCb();

		// 								collection[serviceLower][callKey][location].data = data;

		// 								if (callObj.rateLimit) {
		// 									setTimeout(function(){
		// 										locationCb();
		// 									}, callObj.rateLimit);
		// 								} else {
		// 									locationCb();
		// 								}
		// 							});
		// 						} else {
		// 							executor.runasm(collection, callObj, callKey, function(err, data){
		// 								if (err) {
		// 									collection[serviceLower][callKey][location].err = err;
		// 								}

		// 								if (!data) return locationCb();

		// 								collection[serviceLower][callKey][location].data = data;

		// 								if (callObj.rateLimit) {
		// 									setTimeout(function(){
		// 										locationCb();
		// 									}, callObj.rateLimit);
		// 								} else {
		// 									locationCb();
		// 								}
		// 							});
		// 						}
		// 					}
		// 				}, function () {
		// 					callCb();
		// 				});
		// 			}, function () {
		// 				serviceCb();
		// 			});
		// 		}, function () {
		// 			finalcallCb();
		// 		});
		// 	}, function () {
		// 		//console.log(JSON.stringify(collection, null, 2));
		// 		callback(null, collection);
		// 	});
		// }, function () {
  //           //console.log(JSON.stringify(collection, null, 2));
  //           callback(null, collection);
  //       });
  //   });
};

module.exports = collect;