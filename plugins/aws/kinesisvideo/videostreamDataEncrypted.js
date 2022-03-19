var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Video Stream Data Encrypted',
    category: 'Kinesis Video Streams',
    domain: 'Content Delivery',
    description: 'Ensure that Amazon Kinesis Video Streams is using desired encryption level for Data at-rest.',
    more_info: 'Server-side encryption is always enabled on Kinesis video streams data. If a user-provided key is not specified when the stream is created, the default key (provided by Kinesis Video Streams) is used. ' +
               'It is recommended to use customer-managed keys (CMKs) for encryption in order to gain more granular control over encryption/decryption process.',
    recommended_action: 'Encrypt Kinesis Video Streams data with customer-manager keys (CMKs).',
    link: 'https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/how-kms.html',
    apis: ['KinesisVideo:listStreams', 'KMS:describeKey', 'KMS:listKeys'],
    settings: {
        video_stream_data_desired_encryption_level: {
            name: 'Kinesis Video Streams Data Target Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            desiredEncryptionLevelString: settings.video_stream_data_desired_encryption_level || this.settings.video_stream_data_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.kinesisvideo, function(region, rcb){
            var listStreams = helpers.addSource(cache, source,
                ['kinesisvideo', 'listStreams', region]);
          
            if (!listStreams) return rcb();

            if (listStreams.err || !listStreams.data) {
                helpers.addResult(results, 3, `Unable to query Kinesis Video Streams: ${helpers.addError(listStreams)}`, region);
                return rcb();
            }

            if (!listStreams.data.length) {
                helpers.addResult(results, 0, 'No Kinesis Video Streams found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let streamData of listStreams.data) {
                if (!streamData.StreamARN) continue;

                let resource = streamData.StreamARN;

                if (streamData.KmsKeyId) {
                    var kmsKeyId = streamData.KmsKeyId.split('/')[1] ? streamData.KmsKeyId.split('/')[1] : streamData.KmsKeyId;

                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, kmsKeyId]);  

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, streamData.KmsKeyId);
                        continue;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                } else currentEncryptionLevel = 2; //awskms

                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `Kinesis Video Streams data is using ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `Kinesis Video Streams data is using ${currentEncryptionLevelString} \
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