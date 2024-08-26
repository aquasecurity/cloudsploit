var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Firehose Delivery Stream Destination CMK Encrypted',
    category: 'Firehose',
    domain: 'Content Delivery',
    severity: 'High',
    description: 'Ensures Firehose delivery stream data records are encrypted at destination bucket using AWS KMS key of desired encryption level.',
    more_info: 'Encrypting Kinesis Firehose delivery stream data records at the destination S3 bucket is crucial for compliance and data security. This ensures that data is protected at rest, meeting regulatory requirements and providing an additional layer of security, essential for organizations with strict data protection mandates.',
    recommended_action: 'Enable encryption using desired level for all Firehose Delivery Streams destination S3 bucket.',
    link: 'https://docs.aws.amazon.com/firehose/latest/dev/encryption.html',
    apis: ['Firehose:listDeliveryStreams', 'Firehose:describeDeliveryStream', 'KMS:describeKey', 'KMS:listKeys',
        'STS:getCallerIdentity','S3:getBucketEncryption', 'S3:listBuckets'],
    settings: {
        delivery_stream_desired_encryption_level: {
            name: 'Firehose Delivery Stream Target Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awskms'
        }
    },
    realtime_triggers: ['firehose:CreateDeliveryStreams','firehose:UpdateDestination', 'firehose:DeleteliveryStreams'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var defaultRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', defaultRegion, 'data']);

        var config = {
            desiredEncryptionLevelString: settings.delivery_stream_desired_encryption_level || this.settings.delivery_stream_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);

        async.each(regions.firehose, function(region, rcb){
            var listDeliveryStreams = helpers.addSource(cache, source,
                ['firehose', 'listDeliveryStreams', region]);

            if (!listDeliveryStreams) return rcb();

            if (listDeliveryStreams.err || !listDeliveryStreams.data) {
                helpers.addResult(results, 3,
                    'Unable to list Firehose delivery streams: ' + helpers.addError(listDeliveryStreams), region);
                return rcb();
            }

            if (!listDeliveryStreams.data.length) {
                helpers.addResult(results, 0, 'No Firehose delivery streams found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let stream of listDeliveryStreams.data) {
                var resource = `arn:${awsOrGov}:firehose:${region}:${accountId}:deliverystream/${stream}`;

                var describeDeliveryStream = helpers.addSource(cache, source,
                    ['firehose', 'describeDeliveryStream', region, stream]);

                if (!describeDeliveryStream || describeDeliveryStream.err || !describeDeliveryStream.data ) {
                    helpers.addResult(results, 3,
                        'Unable to query Firehose for delivery streams: ',
                        region, resource);
                    continue;
                }

                let deliveryStreamDesc = describeDeliveryStream.data && describeDeliveryStream.data.DeliveryStreamDescription ? describeDeliveryStream.data.DeliveryStreamDescription : null;
                let kmsKeyId;

                if (!deliveryStreamDesc ||
                    !deliveryStreamDesc.Destinations ||
                    !deliveryStreamDesc.Destinations[0] ||
                    !deliveryStreamDesc.Destinations[0].ExtendedS3DestinationDescription) {
                    helpers.addResult(results, 0,
                        'The Firehose delivery stream does not have an S3 destination',
                        region, resource);
                    continue;
                }
                if (desiredEncryptionLevel === 2) {
                    helpers.addResult(results, 0,
                        `Firehose delivery stream is encrypted with awskms \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    if (deliveryStreamDesc &&
                        deliveryStreamDesc.Destinations &&
                        deliveryStreamDesc.Destinations[0] &&
                        deliveryStreamDesc.Destinations[0].ExtendedS3DestinationDescription &&
                        deliveryStreamDesc.Destinations[0].ExtendedS3DestinationDescription.EncryptionConfiguration &&
                        deliveryStreamDesc.Destinations[0].ExtendedS3DestinationDescription.EncryptionConfiguration.KMSEncryptionConfig &&
                        deliveryStreamDesc.Destinations[0].ExtendedS3DestinationDescription.EncryptionConfiguration.KMSEncryptionConfig.AWSKMSKeyARN) {

                        kmsKeyId = deliveryStreamDesc.Destinations[0].ExtendedS3DestinationDescription.EncryptionConfiguration.KMSEncryptionConfig.AWSKMSKeyARN;
                        processEncryptionLevels(kmsKeyId, region, resource);

                    } else {
                        var bucketName = deliveryStreamDesc.Destinations[0].ExtendedS3DestinationDescription.BucketARN ? deliveryStreamDesc.Destinations[0].ExtendedS3DestinationDescription.BucketARN.split(':::')[1] : null;
                        var getBucketEncryption = helpers.addSource(cache, source,
                            ['s3', 'getBucketEncryption', region, bucketName]);

                        if (getBucketEncryption && getBucketEncryption.err &&
                            getBucketEncryption.err.code && getBucketEncryption.err.code == 'ServerSideEncryptionConfigurationNotFoundError') {
                            helpers.addResult(results, 2,'Firehose delivery stream destination bucket does not have encryption enable' ,region, resource);
                            continue;
                        }
                        if (!getBucketEncryption || getBucketEncryption.err || !getBucketEncryption.data) {
                            helpers.addResult(results, 3,
                                'Error querying bucket encryption for: ' + bucketName +
                                ': ' + helpers.addError(getBucketEncryption),
                                region, resource);

                        } else {
                            var encryption = getBucketEncryption.data.ServerSideEncryptionConfiguration &&
                            getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules &&
                            getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0] &&
                            getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault? getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault : {};
                            if (encryption.SSEAlgorithm && encryption.SSEAlgorithm === 'AES256') {
                                helpers.addResult(results, 2,
                                    `Firehose delivery stream destination bucket is encrypted with awskms \
                                        which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                                    region, resource);
                            } else {
                                kmsKeyId = encryption.KMSMasterKeyID ? encryption.KMSMasterKeyID : null;
                                processEncryptionLevels(kmsKeyId, region, resource);
                            }
                        }
                    }
                }

            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
        function processEncryptionLevels(keyArn, region, resource) {
            var currentEncryptionLevel;

            var keyId = keyArn && keyArn.split('/')[1] ? keyArn.split('/')[1] : '';

            var describeKey = helpers.addSource(cache, source,
                ['kms', 'describeKey', region, keyId]);

            if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                helpers.addResult(results, 3,
                    `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                    region, keyArn);
                return;
            }

            currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);

            var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

            if (currentEncryptionLevel >= desiredEncryptionLevel) {
                helpers.addResult(results, 0,
                    `Firehose delivery stream destination bucket is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                    region, resource);
            } else {
                helpers.addResult(results, 2,
                    `Firehose delivery stream destination bucket is encrypted with ${currentEncryptionLevelString} \
                        which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                    region, resource);
            }

        }
    }
};

