var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Geoference Collection Data Encrypted',
    category: 'Location',
    domain: 'Application Integration',
    description: 'Ensure that Amazon Location geoference collection data is encrypted using desired KMS encryption level.',
    more_info: 'Amazon Location Service provides encryption by default to protect sensitive customer data at rest using AWS owned encryption keys. ' +
        'It is recommended to use customer-managed keys instead in order to gain more granular control over encryption/decryption process.',
    recommended_action: 'Encrypt Amazon Location geoference collection with customer-manager keys (CMKs)',
    link: 'https://docs.aws.amazon.com/location/latest/developerguide/encryption-at-rest.html',
    apis: ['Location:listGeofenceCollections','Location:describeGeofenceCollection', 'KMS:describeKey', 'KMS:listKeys', 'STS:getCallerIdentity'],
    settings: {
        geoference_collectiondata_desired_encryption_level: {
            name: 'Location Geoference Collection Data Target Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var defaultRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', defaultRegion, 'data']);

        var config = {
            desiredEncryptionLevelString: settings.geoference_collectiondata_desired_encryption_level || this.settings.geoference_collectiondata_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.location, function(region, rcb){        
            var listGeofenceCollections = helpers.addSource(cache, source,
                ['location', 'listGeofenceCollections', region]);

            if (!listGeofenceCollections) return rcb();

            if (listGeofenceCollections.err || !listGeofenceCollections.data) {
                helpers.addResult(results, 3,
                    'Unable to query Location geoference collection: ' + helpers.addError(listGeofenceCollections), region);
                return rcb();
            }

            if (!listGeofenceCollections.data.length) {
                helpers.addResult(results, 0, 'No Location geoference collections found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);


            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let collection of listGeofenceCollections.data) {
                var resource = `arn:${awsOrGov}:geo:${region}:${accountId}:geofence-collection/${collection.CollectionName}`;

                var describeGeofenceCollection = helpers.addSource(cache, source,
                    ['location', 'describeGeofenceCollection', region, collection.CollectionName]);


                if (!describeGeofenceCollection || describeGeofenceCollection.err || !describeGeofenceCollection.data) {
                    helpers.addResult(results, 3,
                        `Unable to get Location geoference collection: ${helpers.addError(describeGeofenceCollection)}`,
                        region, resource);
                    continue;
                } 

                if (describeGeofenceCollection.data.KmsKeyId) {
                    var kmsKey = describeGeofenceCollection.data.KmsKeyId;
                    var keyId = kmsKey.split('/')[1] ? kmsKey.split('/')[1] : kmsKey;

                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, keyId]);  

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, kmsKey);
                        continue;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                } else currentEncryptionLevel = 2; //awskms

                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `Geoference collection data is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `Geoference collection data is encrypted with ${currentEncryptionLevelString} \
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