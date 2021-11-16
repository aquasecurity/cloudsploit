var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'MSK Cluster At-Rest Encrypted',
    category: 'MSK',
    domain: 'Application Integration',
    description: 'Ensure that Amazon Managed Streaming for Kafka (MSK) clusters are using AWS KMS Customer Master Keys (CMKs) instead of AWS managed-keys',
    more_info: 'Use your own AWS KMS Customer Master Keys (CMKs) to protect your Managed Streaming for Kafka (MSK) clusters in order to have a fine-grained control over data-at-rest encryption/decryption process and meet compliance requirements.',
    recommended_action: 'Encrypt MSK Cluster At-Rest with desired encryption level',
    link: 'https://docs.aws.amazon.com/msk/1.0/apireference/clusters-clusterarn-security.html',
    apis: ['Kafka:listClusters', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        msk_cluster_at_rest_encryption_level: {
            name: 'MSK Cluster At-Rest Target Encryption Level',
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
            desiredEncryptionLevelString: settings.msk_cluster_at_rest_encryption_level || this.settings.msk_cluster_at_rest_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.kafka, function(region, rcb){
            var listClusters = helpers.addSource(cache, source,
                ['kafka', 'listClusters', region]);

            if (!listClusters) return rcb();

            if (listClusters.err || !listClusters.data) {
                helpers.addResult(results, 3,
                    `Unable to list MSK Cluster At-Rest  : ${helpers.addError(listClusters)}`, region);
                return rcb();
            }

            if (!listClusters.data.length) {
                helpers.addResult(results, 0,
                    'No MSK Clusters found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let cluster of listClusters.data) {
                if (!cluster.ClusterArn) continue;

                let resource = cluster.ClusterArn;

                if (cluster.EncryptionInfo &&
                    cluster.EncryptionInfo.EncryptionAtRest &&
                    cluster.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId) {

                    let DataVolumeKMSKeyId = cluster.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId;  
                    var keyId = DataVolumeKMSKeyId.split('/')[1] ? DataVolumeKMSKeyId.split('/')[1] : DataVolumeKMSKeyId;

                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, keyId]); 

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, DataVolumeKMSKeyId);
                        continue;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                    var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
                        helpers.addResult(results, 0,
                            `MSK Cluster At-Rest is encrypted with ${currentEncryptionLevelString} \
                            which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `MSK Cluster At-Rest is encrypted with ${currentEncryptionLevelString} \
                            which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    }
                } else {
                    helpers.addResult(results, 2,
                        'MSK Cluster At-Rest does not have encryption enabled for assets',
                        region, resource);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};