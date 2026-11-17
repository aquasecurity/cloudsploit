var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElastiCache Serverless Cache KMS Key',
    category: 'ElastiCache',
    domain: 'Databases',
    severity: 'High',
    description: 'Ensures that ElastiCache serverless caches are encrypted with a KMS key of the account.',
    more_info: 'Serverless caches that are not configured with a KMS key are encrypted with an AWS owned key. ' +
        'A KMS key of the account gives control over the key policy, rotation and access auditing.',
    link: 'https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/at-rest-encryption.html',
    recommended_action: 'Create the serverless cache with a customer managed KMS key. The key of an existing cache cannot be changed, so recreate it from a snapshot with a KMS key.',
    apis: ['ElastiCache:describeServerlessCaches', 'KMS:listKeys', 'STS:getCallerIdentity'],
    realtime_triggers: ['elasticache:CreateServerlessCache', 'elasticache:DeleteServerlessCache'],

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

            var listKeys = helpers.addSource(cache, source, ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    'Unable to list KMS keys: ' + helpers.addError(listKeys), region);
                return rcb();
            }

            // The key is returned as a key id or as a key ARN
            var keys = [];
            listKeys.data.forEach(function(key) { keys.push(key.KeyArn, key.KeyId); });

            describeServerlessCaches.data.forEach(function(serverlessCache) {
                var resource = serverlessCache.ARN || serverlessCache.ServerlessCacheName;

                if (serverlessCache.KmsKeyId && keys.indexOf(serverlessCache.KmsKeyId) > -1) {
                    helpers.addResult(results, 0,
                        'ElastiCache serverless cache is encrypted with a KMS key of the account', region, resource);
                } else if (serverlessCache.KmsKeyId) {
                    helpers.addResult(results, 2,
                        'ElastiCache serverless cache uses a KMS key that is not a key of the account', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'ElastiCache serverless cache does not use a customer managed KMS key', region, resource);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
