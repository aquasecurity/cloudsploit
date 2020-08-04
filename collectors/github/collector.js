'use strict';

/*********************
 Collector - The collector will query GitHub APIs for the information required
 to run the CloudSploit scans. This data will be returned in the callback
 as a JSON object.
 *********************/

var Octokit = require('@octokit/rest');
var Octoapp = require('@octokit/app');
var Octoreq = require('@octokit/request');
var async = require('async');

var collectors = require(__dirname + '/../../collectors/github');
var helpers = require(__dirname + '/../../helpers/github');

var calls = {
    apps: {
        listRepos: {
            type: 'server',
            paginate: 'self',
            params: {
                per_page: 100
            }
        }
    },
    orgs: {
        get: {
            type: 'server',
            inject_org: true
        },
        listForAuthenticatedUser: {
            type: 'server',
            params: {
                per_page: 100
            }
        },
        listMembers: {
            type: 'server',
            inject_org: true,
            paginate: 'self',
            params: {
                per_page: 100
            }
        }
    },
    teams: {
        list: {
            type: 'server',
            inject_org: true
        }
    },
    users: {
        listPublicKeys: {
            type: 'user',
            params: {
                per_page: 100
            }
        },
        listGpgKeys: {
            type: 'user',
            params: {
                per_page: 100
            }
        },
        getAuthenticated: {
            type: 'user',
            params: {}
        },
        listEmails: {
            type: 'user',
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
                type: 'server',
                inject_org: true,
                reliesOnService: 'orgs',
                reliesOnCall: 'listMembers',
                filterKey: 'username',
                filterValue: 'login'
            }
        },
        repos: {
            listDeployKeys: {
                override: true,
                type: 'server'
            },
            listCollaborators: {
                override: true,
                type: 'server'
            }
        }
    }
];

// Loop through all of the top-level collectors for each service
var collect = function(GitHubConfig, settings, callback) {
    var collection = {};
    var appConfig = { id: GitHubConfig.application_id, privateKey: GitHubConfig.private_key };
    if (GitHubConfig.url) appConfig.baseUrl = GitHubConfig.url;

    const app = new Octoapp(appConfig);
    const jwt = app.getSignedJsonWebToken();

    var reqObj = {
        headers: {
            authorization: `Bearer ${jwt}`,
            accept: 'application/vnd.github.machine-man-preview+json'
        }
    };

    var path = GitHubConfig.organization ? '/orgs/:org/installation' : '/users/:username/installation';
    var param = GitHubConfig.organization ? 'org' : 'username';
    reqObj[param] = GitHubConfig.login;

    Octoreq('GET ' + path, reqObj).then(function(data){
        if (!data || !data.data || !data.data.id) return callback('No installation ID found. Please ensure the GitHub app is installed.');

        var installationId = data.data.id;

        if (GitHubConfig.installation_id && GitHubConfig.installation_id !== installationId) {
            return callback('Installation ID misconfigured. Please reinstall the GitHub app.');
        }

        app.getInstallationAccessToken({ installationId }).then(function(installationToken){
            if (!installationToken) return callback('Installation token could not be obtained. Please ensure the GitHub app is installed.');

            var octokit = {
                server: new Octokit({
                    baseUrl: GitHubConfig.url,
                    auth: 'token ' + installationToken,
                    previews: [
                        'hellcat-preview',
                        'machine-man-preview'
                    ]
                }),
                user: new Octokit({
                    baseUrl: GitHubConfig.url,
                    auth: 'token ' + GitHubConfig.access_token,
                    previews: [
                        'hellcat-preview',
                        'machine-man-preview'
                    ]
                })
            };

            var processPagination = function(callObj, results) {
                if (callObj.paginate && results) {
                    if (callObj.paginate !== 'self') {
                        var masterList = [];
                        for (var r in results) {
                            if (results[r][callObj.paginate]) masterList = masterList.concat(results[r][callObj.paginate]);
                        }
                        results = masterList;
                    }

                    return results;
                } else if (results && results.data) {
                    return results.data;
                } else {
                    return null;
                }
            };

            async.eachOfLimit(calls, 10, function(call, service, serviceCb){
                if (!collection[service]) collection[service] = {};

                // Loop through each of the service's functions
                async.eachOfLimit(call, 10, function(callObj, callKey, callCb) {
                    if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return callCb();
                    if (!collection[service][callKey]) collection[service][callKey] = {};

                    var params = callObj.params || {};
                    if (callObj.inject_org) params.org = GitHubConfig.login;
                    var type = callObj.type;

                    var finish = function() {
                        if (callObj.rateLimit) {
                            setTimeout(function() {
                                callCb();
                            }, callObj.rateLimit);
                        } else {
                            callCb();
                        }
                    };

                    if (callObj.override) {
                        collectors[service][callKey](GitHubConfig, octokit[type], collection, function() {
                            finish();
                        });
                    } else {
                        var processResults = function(results){
                            collection[service][callKey].data = processPagination(callObj, results);
                            finish();
                        };

                        var processErr = function(err){
                            if (err) collection[service][callKey].err = err;
                            finish();
                        };

                        if (callObj.paginate) {
                            var options = octokit[type][service][callKey].endpoint.merge(params);
                            octokit[type].paginate(options).then(processResults, processErr);
                        } else {
                            octokit[type][service][callKey](params).then(processResults, processErr);
                        }
                    }
                }, function(){
                    serviceCb();
                });
            }, function(){
                // Now loop through the follow up calls
                async.eachSeries(postcalls, function(postcallObj, postcallCb) {
                    async.eachOfLimit(postcallObj, 10, function(serviceObj, service, serviceCb) {
                        if (!collection[service]) collection[service] = {};

                        async.eachOfLimit(serviceObj, 1, function(callObj, callKey, callCb) {
                            if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return callCb();
                            if (!collection[service][callKey]) collection[service][callKey] = {};

                            // Ensure pre-requisites are met
                            if (callObj.reliesOnService && !collection[callObj.reliesOnService]) return callCb();

                            if (callObj.reliesOnCall &&
                                (!collection[callObj.reliesOnService] ||
                                !collection[callObj.reliesOnService][callObj.reliesOnCall] ||
                                !collection[callObj.reliesOnService][callObj.reliesOnCall].data ||
                                !collection[callObj.reliesOnService][callObj.reliesOnCall].data.length)) return callCb();

                            var type = callObj.type;

                            if (callObj.override) {
                                collectors[service][callKey](GitHubConfig, octokit[type], collection, function() {
                                    if (callObj.rateLimit) {
                                        setTimeout(function() {
                                            callCb();
                                        }, callObj.rateLimit);
                                    } else {
                                        callCb();
                                    }
                                });
                            } else {
                                if (!callObj.reliesOnService && !callObj.reliesOnCall) {
                                    var params = callObj.params || {};
                                    if (callObj.inject_org) params.org = GitHubConfig.login;

                                    var processResults = function(results){
                                        collection[service][callKey].data = processPagination(callObj, results);
                                        callCb();
                                    };

                                    var processErr = function(err){
                                        collection[service][callKey].err = err;
                                        callCb();
                                    };

                                    if (callObj.paginate) {
                                        var options = octokit[type][service][callKey].endpoint.merge(params);
                                        octokit[type].paginate(options).then(processResults, processErr);
                                    } else {
                                        octokit[type][service][callKey](params).then(processResults, processErr);
                                    }
                                } else {
                                    async.eachLimit(collection[callObj.reliesOnService][callObj.reliesOnCall].data, 10, function(dep, depCb) {
                                        collection[service][callKey][dep[callObj.filterValue]] = {};

                                        var filter = {};
                                        if (callObj.inject_org) filter.org = GitHubConfig.login;
                                        filter[callObj.filterKey] = dep[callObj.filterValue];

                                        var processResults = function(results){
                                            collection[service][callKey][dep[callObj.filterValue]].data = processPagination(callObj, results);
                                            depCb();
                                        };

                                        var processErr = function(err){
                                            collection[service][callKey][dep[callObj.filterValue]].err = err;
                                            depCb();
                                        };

                                        if (callObj.paginate) {
                                            var options = octokit[type][service][callKey].endpoint.merge(filter);
                                            octokit[type].paginate(options).then(processResults, processErr);
                                        } else {
                                            octokit[type][service][callKey](filter).then(processResults, processErr);
                                        }
                                    }, function() {
                                        if (callObj.rateLimit) {
                                            setTimeout(function() {
                                                callCb();
                                            }, callObj.rateLimit);
                                        } else {
                                            callCb();
                                        }
                                    });
                                }
                            }
                        }, function() {
                            serviceCb();
                        });
                    }, function() {
                        postcallCb();
                    });
                }, function() {
                    //console.log(JSON.stringify(collection, null, 2));
                    helpers.cleanCollection(collection);
                    callback(null, collection);
                });
            });
        });
    }).catch(function(err){
        callback(err);
    });
};

module.exports = collect;