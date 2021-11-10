var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'DocumentDB Cluster Encrypted',
    category: 'DocumentDB',
    domain: 'Databases',
    description: 'Ensure that your AWS DocumentDB clusters data is encrypted with KMS Customer Master Keys (CMKs) instead of AWS managed-keys.',
    more_info: 'Use your own AWS KMS Customer Master Keys (CMKs) to protect your DocumentDB data (including indexes, logs, replicas and snapshots) from unauthorized users, you have full control over who can use the encryption keys to access your data.',
    recommended_action: 'Encrypt DocumentDB Cluster with desired encryption level',
    link: 'https://docs.aws.amazon.com/documentdb/latest/developerguide/what-is.html#what-is-db-clusters',
    apis: ['DocDB:describeDBClusters', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        documentdb_cluster_encryption_level: {
            name: 'DocumentDB Cluster Target Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk',
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            desiredEncryptionLevelString: settings.documentdb_cluster_encryption_level || this.settings.documentdb_cluster_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;
    
        async.each(regions.docdb, function(region, rcb){
            var describeDBClusters = helpers.addSource(cache, source,
                ['docdb', 'describeDBClusters', region]);

            if (!describeDBClusters) return rcb();

            if (describeDBClusters.err || !describeDBClusters.data) {
                helpers.addResult(results, 3,
                    `Unable to list DocumentDB Clusters : ${helpers.addError(describeDBClusters)}`, region);
                return rcb();
            }

            if (!describeDBClusters.data.length) {
                helpers.addResult(results, 0,
                    'No DB Clusters found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }
            
            for (let cluster of describeDBClusters.data) {
                if (!cluster.DBClusterArn) continue;

                let resource = cluster.DBClusterArn;

                if (cluster.KmsKeyId) {
                    var kmsKeyId = cluster.KmsKeyId.split('/')[1] ? cluster.KmsKeyId.split('/')[1] : cluster.KmsKeyId;

                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, kmsKeyId]); 

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, kmsKeyId);
                        continue;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                    var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
                        helpers.addResult(results, 0,
                            `DocumentDB Cluster is encrypted with ${currentEncryptionLevelString} \
                            which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `DocumentDB Cluster is encrypted with ${currentEncryptionLevelString} \
                            which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    }
                } else {
                    helpers.addResult(results, 2,
                        'DynamoDB Clusters does not have encryption enabled for assets',
                        region, resource);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};