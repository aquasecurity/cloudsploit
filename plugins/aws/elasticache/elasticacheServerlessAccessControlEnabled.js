var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElastiCache Serverless Cache Access Control Enabled',
    category: 'ElastiCache',
    domain: 'Databases',
    severity: 'High',
    description: 'Ensures that ElastiCache serverless caches have access control enabled with a user group.',
    more_info: 'Without a user group, every client that can reach the endpoint of the serverless cache can use the default user. ' +
        'Role-based access control with a user group restricts who can connect and which commands they can run.',
    link: 'https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/Clusters.RBAC.html',
    recommended_action: 'Modify the ElastiCache serverless cache to use a user group with access control (RBAC).',
    apis: ['ElastiCache:describeServerlessCaches'],
    realtime_triggers: ['elasticache:CreateServerlessCache', 'elasticache:ModifyServerlessCache', 'elasticache:DeleteServerlessCache'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.elasticache, function(region, rcb) {
            var describeServerlessCaches = helpers.addSource(cache, source, ['elasticache', 'describeServerlessCaches', region]);

            if (!describeServerlessCaches) return rcb();

            if (describeServerlessCaches.err || !describeServerlessCaches.data) {
                helpers.addResult(results, 3,
                    'Unable to query for ElastiCache serverless caches: ' + helpers.addError(describeServerlessCaches), region);
                return rcb();
            }

            if (!describeServerlessCaches.data.length) {
                helpers.addResult(results, 0, 'No ElastiCache serverless caches found', region);
                return rcb();
            }

            describeServerlessCaches.data.forEach(function(serverlessCache) {
                var resource = serverlessCache.ARN || serverlessCache.ServerlessCacheName;

                if (serverlessCache.UserGroupId) {
                    helpers.addResult(results, 0, 'ElastiCache serverless cache has access control enabled', region, resource);
                } else {
                    helpers.addResult(results, 2, 'ElastiCache serverless cache does not have access control enabled', region, resource);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
