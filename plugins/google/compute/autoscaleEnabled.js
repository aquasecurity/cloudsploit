var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Autoscale Enabled',
    category: 'Compute',
    description: 'Ensures instance groups have autoscale enabled for high availability',
    more_info: 'Enabling autoscale increases efficiency and improves cost management for resources.',
    link: 'https://cloud.google.com/compute/docs/autoscaler/',
    recommended_action: 'Ensure autoscaling is enabled for all instance groups.',
    apis: ['instanceGroups:aggregatedList', 'autoscalers:aggregatedList','clusters:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var instanceGroupURLObj = {};

        let instanceGroupsObj = helpers.addSource(cache, source,
            ['instanceGroups', 'aggregatedList', ['global']]);

        if (instanceGroupsObj.err || !instanceGroupsObj.data) {
            helpers.addResult(results, 3, 'Unable to query instance groups: ' + helpers.addError(instanceGroupsObj), 'global');
            return callback(null, results, source);
        }

        var instanceGroups = Object.values(instanceGroupsObj.data).filter(instanceGroup =>{
            return !instanceGroup.warning;
        });

        if (!instanceGroups.length) {
            helpers.addResult(results, 0, 'No instance groups found', 'global');
            return callback(null, results, source);
        }

        async.each(instanceGroups, function(instanceGroupsInLocation, rcb) {
            instanceGroupsInLocation.instanceGroups.forEach(instanceGroup => {
                if (instanceGroup.name) {
                    instanceGroupURLObj[instanceGroup.name] = instanceGroup
                }
            });

            return rcb();
        }, function() {
            let clusters = helpers.addSource(cache, source,
                ['clusters', 'list', ['global']]);

            if (clusters.err || !clusters.data) {
                helpers.addResult(results, 3, 'Unable to query autoscalers: ' + helpers.addError(clusters), 'global');
            } else if (!clusters.data.length) {
                helpers.addResult(results, 0, 'No instance groups found', 'global');
            } else {
                clusters.data.forEach(cluster => {
                    if (cluster.nodePools &&
                    cluster.nodePools.length) {
                        cluster.nodePools.forEach(nodePool => {
                            if (nodePool.autoscaling &&
                                nodePool.autoscaling.enabled &&
                                nodePool.instanceGroupUrls &&
                                nodePool.instanceGroupUrls.length) {
                                nodePool.instanceGroupUrls.forEach(instanceGroupUrl => {
                                    var instanceGroupUrlName = instanceGroupUrl.split('/')[10];
                                    if (instanceGroupURLObj.hasOwnProperty(instanceGroupUrlName)) {
                                        delete instanceGroupURLObj[instanceGroupUrlName]
                                    }
                                });
                            }
                        });
                    }
                });
            }

            let autoscalersObj = helpers.addSource(cache, source,
                ['autoscalers', 'aggregatedList', ['global']]);

            if (autoscalersObj.err || !autoscalersObj.data) {
                helpers.addResult(results, 3, 'Unable to query autoscalers: ' + helpers.addError(autoscalersObj), 'global');
            } else {
                var autoscalers = Object.values(autoscalersObj.data).filter(autoscaler =>{
                    return !autoscaler.warning;
                });
            }

            if (autoscalers.length) {
                async.each(autoscalers, function(autoscalersInLocation, lcb) {
                    autoscalersInLocation.autoscalers.forEach(autoscaler => {
                        if (autoscaler.name) {
                            if (instanceGroupURLObj.hasOwnProperty(autoscaler.name)) {
                                delete instanceGroupURLObj[autoscaler.name]
                            }
                        }
                    });

                    lcb();
                }, function() {
                    if (Object.keys(instanceGroupURLObj).length) {
                        let instanceGroupStr = Object.values(instanceGroupURLObj).map(a => a.id).join(', ');
                        helpers.addResult(results, 2,
                            `The following instance groups do not have autoscale enabled: ${instanceGroupStr}`, 'global');
                    } else {
                        helpers.addResult(results, 0,
                            'All instance groups have autoscale enabled', 'global');
                    }
                    callback(null, results, source);
                });
            } else {
                if (Object.keys(instanceGroupURLObj).length) {
                    let instanceGroupStr = Object.values(instanceGroupURLObj).map(a => a.id).join(', ');
                    helpers.addResult(results, 2,
                        `The following instance groups do not have autoscale enabled: ${instanceGroupStr}`, 'global');
                } else {
                    helpers.addResult(results, 0,
                        'All instance groups have autoscale enabled', 'global');
                }
                callback(null, results, source);
            }
        });
    }
};