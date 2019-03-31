"use strict";

/*********************
 Collector - The collector will query GitHub APIs for the information required
 to run the CloudSploit scans. This data will be returned in the callback
 as a JSON object.
 *********************/

var Octokit = require('@octokit/rest');
var async = require('async');
var util = require('util');

var collectors = require(__dirname + '/../../collectors/github');

var calls = {
	apps: {
		listInstallationsForAuthenticatedUser: {
			type: 'token',
			params: {
				per_page: 100
			}
		}
	},
	orgs: {
		get: {
			type: 'token',
			inject_org: true
		},
		listForAuthenticatedUser: {
			type: 'token',
			params: {
				per_page: 100
			}
		},
		listMembers: {
			type: 'token',
			inject_org: true,
			params: {
				per_page: 100
			}
		}
	},
	repos: {
		listForOrg: {
			type: 'token',
			inject_org: true
		}
	},
	teams: {
		list: {
			type: 'token',
			inject_org: true
		}
	},
	users: {
		listPublicKeys: {
			type: 'token',
			params: {
				per_page: 100
			}
		},
		listGpgKeys: {
			type: 'token',
			params: {
				per_page: 100
			}
		},
		getAuthenticated: {
			type: 'token',
			params: {}
		},
		listEmails: {
			type: 'token',
			params: {
				per_page: 100
			}
		}
	}
};

var postcalls = [
	{
		orgs: {
			getMembership: {
				type: 'token',
				inject_org: true,
				reliesOnService: 'orgs',
				reliesOnCall: 'listMembers',
				filterKey: 'username',
				filterValue: 'login'
			}
		}
	}
];

var collection = {};

// Loop through all of the top-level collectors for each service
var collect = function (GitHubConfig, settings, callback) {
	var octokit = {
		token: new Octokit({
			baseUrl: GitHubConfig.url,
			auth: 'token ' + GitHubConfig.token,
			previews: [
				'hellcat-preview'
			]
		}),
		// oauth: new Octokit({
		// 	baseUrl: GitHubConfig.url,
		// 	auth: {
		// 		clientId: GitHubConfig.clientId,
		// 		clientSecret: GitHubConfig.clientSecret
		// 	},
		// 	previews: [
		// 		'hellcat-preview'
		// 	]
		// })
	};

	async.eachOfLimit(calls, 10, function(call, service, serviceCb){
		if (!collection[service]) collection[service] = {};

		// Loop through each of the service's functions
		async.eachOfLimit(call, 10, function (callObj, callKey, callCb) {
			if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return callCb();
			if (!collection[service][callKey]) collection[service][callKey] = {};

			var params = callObj.params || {};
			if (callObj.inject_org) params.org = GitHubConfig.org;

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
				collectors[service][callKey](octokit, collection, function () {
					finish();
				});
			} else {
				octokit[callObj.type][service][callKey](params).then(function(results){
					if (results && results.data) collection[service][callKey].data = results.data;
					finish();
				}, function(err){
					if (err) collection[service][callKey].err = err;
					finish();
				});
			}
		}, function(){
			serviceCb();
		});
	}, function(){
		// Now loop through the follow up calls
		async.eachSeries(postcalls, function (postcallObj, postcallCb) {
		    async.eachOfLimit(postcallObj, 10, function (serviceObj, service, serviceCb) {
		        if (!collection[service]) collection[service] = {};

		        async.eachOfLimit(serviceObj, 1, function (callObj, callKey, callCb) {
		            if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return callCb();
		            if (!collection[service][callKey]) collection[service][callKey] = {};

		            // Ensure pre-requisites are met
		            if (callObj.reliesOnService && !collection[callObj.reliesOnService]) return callCb();

		            if (callObj.reliesOnCall &&
		                (!collection[callObj.reliesOnService] ||
		                !collection[callObj.reliesOnService][callObj.reliesOnCall] ||
		                !collection[callObj.reliesOnService][callObj.reliesOnCall].data ||
		                !collection[callObj.reliesOnService][callObj.reliesOnCall].data.length)) return callCb();

		            if (callObj.override) {
		                collectors[service][callKey](octokit, collection, function () {
		                    if (callObj.rateLimit) {
		                        setTimeout(function () {
		                            callCb();
		                        }, callObj.rateLimit);
		                    } else {
		                        callCb();
		                    }
		                });
		            } else {
		                if (!callObj.reliesOnService && !callObj.reliesOnCall) {
		                	var params = callObj.params || {};
		                	if (callObj.inject_org) params.org = GitHubConfig.org;

                	    	octokit[callObj.type][service][callKey](params).then(function(results){
								if (results && results.data) collection[service][callKey].data = results.data;
								depCb();
							}, function(err){
								collection[service][callKey].err = err;
								depCb();
							});
		                } else {
		                	async.eachLimit(collection[callObj.reliesOnService][callObj.reliesOnCall].data, 10, function (dep, depCb) {
		                	    collection[service][callKey][dep[callObj.filterValue]] = {};

		                	    var filter = {};
		                	    if (callObj.inject_org) filter.org = GitHubConfig.org;
		                	    filter[callObj.filterKey] = dep[callObj.filterValue];

                    	    	octokit[callObj.type][service][callKey](filter).then(function(results){
    								if (results && results.data) collection[service][callKey][dep[callObj.filterValue]].data = results.data;
    								depCb();
    							}, function(err){
    								collection[service][callKey][dep[callObj.filterValue]].err = err;
    								depCb();
    							});
		                	}, function () {
		                	    if (callObj.rateLimit) {
		                	        setTimeout(function () {
		                	            callCb();
		                	        }, callObj.rateLimit);
		                	    } else {
		                	        callCb();
		                	    }
		                	});
		                }
		            }
		        }, function () {
		            serviceCb();
		        });
		    }, function () {
		        postcallCb();
		    });
		}, function () {
		    //console.log(JSON.stringify(collection, null, 2));
		    callback(null, collection);
		});
	});
};

module.exports = collect;