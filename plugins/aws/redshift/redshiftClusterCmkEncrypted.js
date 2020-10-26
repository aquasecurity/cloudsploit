var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Redshift Cluster CMK Encryption',
    category: 'Redshift',
    description: 'Ensures Redshift clusters are encrypted using KMS customer master keys (CMKs)',
    more_info: 'KMS CMKs should be used to encrypt redshift clusters in order to have full control over data encryption and decryption.',
    link: 'http://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html',
    recommended_action: 'Update Redshift clusters encryption configuration to use KMS CMKs instead of AWS managed-keys.',
    apis: ['Redshift:describeClusters', 'KMS:listAliases', 'STS:getCallerIdentity'],

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

            if (!describeClusters) return rcb();

            if (describeClusters.err || !describeClusters.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Redshift clusters: ${helpers.addError(describeClusters)}`, region);
                return rcb();
            }

            if (!describeClusters.data.length) {
                helpers.addResult(results, 0, 'No Redshift clusters found', region);
                return rcb();
            }

            var listAliases = helpers.addSource(cache, source,
                ['kms', 'listAliases', region]);

            if (!listAliases || listAliases.err || !listAliases.data) {
                helpers.addResult(results, 3,
                    `Unable to query for KMS aliases: ${helpers.addError(listAliases)}`,
                    region);
                return rcb();
            }

            var aliasId;
            var kmsAliases = {};
            //Create an object where key is kms key ARN and value is alias name
            listAliases.data.forEach(function(alias){
                if (alias.AliasArn && alias.TargetKeyId) {
                    aliasId = alias.AliasArn.replace(/:alias\/.*/, ':key/' + alias.TargetKeyId);
                    kmsAliases[aliasId] = alias.AliasName;
                }
            });

            for (var c in describeClusters.data) {
                var cluster = describeClusters.data[c];
                if (!cluster.ClusterIdentifier) continue;

                var clusterIdentifier = cluster.ClusterIdentifier;
                var resource = `arn:${awsOrGov}:redshift:${region}:${accountId}:cluster:${clusterIdentifier}`;

                if (cluster.Encrypted && cluster.KmsKeyId) {
                    if (kmsAliases[cluster.KmsKeyId]) {
                        if (kmsAliases[cluster.KmsKeyId] === 'alias/aws/rds'){
                            helpers.addResult(results, 2,
                                `Redshift cluster "${cluster.ClusterIdentifier}"is not encrypted using KMS customer master key(CMK)`,
                                region, resource);
                        } else {
                            helpers.addResult(results, 0,
                                `Redshift cluster "${cluster.ClusterIdentifier}"is not encrypted using KMS customer master key(CMK)`,
                                region, resource);
                        }
                    }
                    else {
                        helpers.addResult(results, 2,
                            `Redshift cluster encryption key "${cluster.KmsKeyId}" not found`,
                            region, resource);
                    }
                } else {
                    helpers.addResult(results, 2,
                        `Redshift cluster "${cluster.ClusterIdentifier}" does not have encryption enabled`,
                        region, resource);
                }
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
