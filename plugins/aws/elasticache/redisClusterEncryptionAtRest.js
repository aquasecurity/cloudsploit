var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElastiCache Redis Cluster Encryption At-Rest',
    category: 'ElastiCache',
    domain: 'Databases',
    description: 'Ensure that your AWS ElastiCache Redis clusters are encrypted in order to meet security and compliance requirements.',
    more_info: 'Working with production data it is highly recommended to implement encryption in order to protect it from unauthorized access and fulfill compliance requirements for data-at-rest encryption within your organization',
    link: 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/WhatIs.html',
    recommended_action: 'Enable encryption for ElastiCache cluster data-at-rest.',
    apis: ['ElastiCache:describeCacheClusters', 'ElastiCache:describeReplicationGroups', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        ec_at_rest_encryption_level: {
            name: 'ElastiCache Redis Cluster At-Rest Target Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk',
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        console.log(JSON.stringify(cache.elasticache, null, 2));

        var config = {
            desiredEncryptionLevelString: settings.ec_at_rest_encryption_level || this.settings.ec_at_rest_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.elasticache, function(region, rcb){
            var describeCacheClusters = helpers.addSource(cache, source,
                ['elasticache', 'describeCacheClusters', region]);

            if (!describeCacheClusters) return rcb();

            if (describeCacheClusters.err || !describeCacheClusters.data) {
                helpers.addResult(results, 3,
                    `Unable to list ElastiCache Redis Clusters : ${helpers.addError(describeCacheClusters)}`, region);
                return rcb();
            }

            if (!describeCacheClusters.data.length) {
                helpers.addResult(results, 0,
                    'No ElastiCache Redis Cluster found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let cluster of describeCacheClusters.data) {
                if (!cluster.ARN) continue;

                let resource = cluster.ARN;

                if (!cluster.Engine === 'redis'){
                    helpers.addResult(results, 2, `Encryption is not supported for ${cluster.Engine}`, region);
                    continue ;
                }

                if (cluster.AtRestEncryptionEnabled) {

                    let describeReplicationGroups = helpers.addSource(cache, source,
                        ['elasticache', 'describeReplicationGroups', region, cluster.ReplicationGroupId]);

                    if (!describeReplicationGroups || describeReplicationGroups.err || !describeReplicationGroups.data ||
                        !describeReplicationGroups.data.ReplicationGroups || !describeReplicationGroups.data.ReplicationGroups.length) {
                        helpers.addResult(results, 3,
                            `Unable to describe Replication Groups : ${helpers.addError(describeReplicationGroups)}`, region, resource);
                        continue;
                    }
                
                    if (describeReplicationGroups.data.ReplicationGroups[0].KmsKeyId) {
                        var kmsKeyId = describeReplicationGroups.data.ReplicationGroups[0].KmsKeyId.split('/')[1] ? describeReplicationGroups.data.ReplicationGroups[0].KmsKeyId.split('/')[1] : describeReplicationGroups.data.ReplicationGroups[0].KmsKeyId;

                        var describeKey = helpers.addSource(cache, source,
                            ['kms', 'describeKey', region, kmsKeyId]);

                        if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                            helpers.addResult(results, 3,
                                `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                                region, kmsKeyId);
                            continue;
                        }

                        currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                    } else {
                        currentEncryptionLevel = 2; //awskms
                    }

                    var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
                        helpers.addResult(results, 0,
                            `ElastiCache Redis Cluster is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `ElastiCache Redis Cluster is encrypted with ${currentEncryptionLevelString} \
                        which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    }
                } else {
                    helpers.addResult(results, 2,
                        'Cluster does not have encryption Enabled at :' + cluster.CacheClusterId, region, resource);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
}; 