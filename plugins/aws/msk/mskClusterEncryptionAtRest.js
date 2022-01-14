var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'MSK Cluster Encryption At-Rest',
    category: 'MSK',
    domain: 'Compute',
    description: 'Ensure that Amazon Managed Streaming for Kafka (MSK) clusters are using desired encryption key for at-rest encryption.',
    more_info: 'Amazon MSK encrypts all data at rest using AWS-managed KMS keys by default. Use AWS customer-managed Keys (CMKs) instead in order to have a fine-grained control over data-at-rest encryption/decryption process and meet compliance requirements.',
    recommended_action: 'Modify MSK cluster encryption configuration to use desired encryption key',
    link: 'https://docs.aws.amazon.com/msk/1.0/apireference/clusters-clusterarn-security.html',
    apis: ['Kafka:listClusters', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        msk_cluster_desired_encryption_level: {
            name: 'MSK Cluster Desired Encryption Level',
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
            desiredEncryptionLevelString: settings.msk_cluster_desired_encryption_level || this.settings.msk_cluster_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.kafka, function(region, rcb){
            var listClusters = helpers.addSource(cache, source,
                ['kafka', 'listClusters', region]);

            if (!listClusters) return rcb();

            if (listClusters.err || !listClusters.data) {
                helpers.addResult(results, 3,
                    `Unable to list MSK clusters : ${helpers.addError(listClusters)}`, region);
                return rcb();
            }

            if (!listClusters.data.length) {
                helpers.addResult(results, 0,
                    'No MSK clusters found', region);
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
                    let dataVolumeKMSKeyId = cluster.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId;  
                    var keyId = dataVolumeKMSKeyId.split('/')[1] ? dataVolumeKMSKeyId.split('/')[1] : dataVolumeKMSKeyId;

                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, keyId]); 

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, dataVolumeKMSKeyId);
                        continue;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                } else {
                    currentEncryptionLevel = 2; //awskms
                }

                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `MSK cluster is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `MSK cluster is encrypted with ${currentEncryptionLevelString} \
                        which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
