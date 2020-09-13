var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Redshift Cluster Encrypted With KMS Customer Master Keys',
    category: 'Redshift',
    description: 'Ensures Redshift clusters are encrypted using KMS customer master keys (CMKs)',
    more_info: 'KMS CMKs should be used to encrypt redshift clusters in order to have full control over data encryption and decryption.',
    link: 'http://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html',
    recommended_action: 'Update redshift clusters encryption configuration to use KMS CMKs unstead of AWS managed-keys.',
    apis: ['Redshift:describeClusters', 'KMS:listKeys', 'KMS:describeKey', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.redshift, function(region, rcb){
            var describeClusters = helpers.addSource(cache, source,
                ['redshift', 'describeClusters', region]);

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!describeClusters) return rcb();

            if (describeClusters.err || !describeClusters.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Redshift clusters: ' + helpers.addError(describeClusters), region);
                return rcb();
            }

            if (!describeClusters.data.length) {
                helpers.addResult(results, 0, 'No Redshift clusters found', region);
                return rcb();
            }

            if (!listKeys) return rcb();

            if (listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3, 'Unable to list keys' + helpers.addError(listKeys), region);
                return rcb();
            }

            async.each(describeClusters.data, function(cluster, ccb){
                if (!cluster.ClusterIdentifier) return ccb();

                var clusterIdentifier = cluster.ClusterIdentifier;
                var resource = `arn:${awsOrGov}:redshift:${region}:${accountId}:cluster:${clusterIdentifier}`;

                if (cluster.Encrypted && cluster.KmsKeyId) {
                    var kmsKey = listKeys.data.find(key => key.KeyArn === cluster.KmsKeyId);

                    if (kmsKey) {
                        var describeKey = helpers.addSource(cache, source,
                            ['kms', 'describeKey', region, kmsKey.KeyId]);

                        if (!describeKey || describeKey.err || !describeKey.data) {
                            helpers.addResult(results, 3,
                                `Unable to query for Key information: ${helpers.addError(describeKey)}`,
                                region, resource);
                            return ccb();
                        }

                        if (!describeKey.data.KeyMetadata ||
                            !describeKey.data.KeyMetadata.KeyManager) {
                            helpers.addResult(results, 3,
                                `Unable to query for Key metadata: ${helpers.addError(describeKey)}`,
                                region, resource);
                            return ccb();
                        }

                        var keyManager = describeKey.data.KeyMetadata.KeyManager;

                        if(keyManager === 'AWS') {
                            helpers.addResult(results, 2,
                                `Redshift cluster :${clusterIdentifier}: is not encrypted using KMS customer master key(CMK)`,
                                region, resource);
                        } else {
                            helpers.addResult(results, 0,
                                `Redshift cluster :${clusterIdentifier}: is encrypted using KMS customer master key(CMK)`,
                                region, resource);
                        }

                    } else {
                        helpers.addResult(results, 3, `Unable to find KMS key :${cluster.KmsKeyId}`, region, resource);
                    }

                } else {
                    helpers.addResult(results, 2, `Redshift cluster :${clusterIdentifier}: is not encrypted`, region, resource);
                }
            });
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
