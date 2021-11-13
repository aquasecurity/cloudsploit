var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: ' Timestream Database Encrypted',
    category: 'Timestream',
    domain: 'Databases',
    description: 'Ensures that the Timestream Database is Encrypted',
    more_info: 'Amazon Timestream encrypts your output data with AWS-manager keys by default. ' +
               'Encrypt your files using customer-managed keys in order to gain more granular control over encryption/decryption process.',
    recommended_action: 'Create Trimestream Databases with customer-manager keys (CMKs).',
    link: 'https://docs.aws.amazon.com/timestream/latest/developerguide/EncryptionAtRest.html',
    apis: ['TimestreamWrite:listDatabases', 'KMS:describeKey', 'KMS:listKeys'],
    settings: {
        timestream_databases_encryption: {
            name: 'Timestream Databases Encryption',
            description: 'If set, Timestream Databases should have a customer managed key(CMK) instead of default KMS ',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            desiredEncryptionLevelString: settings.timestream_databases_encryption || this.settings.timestream_databases_encryption.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.timestreamwrite, function(region, rcb){
            var listDatabases = helpers.addSource(cache, source,
                ['timestreamwrite', 'listDatabases', region]);
               

            if (!listDatabases) return rcb();

            if (listDatabases.err || !listDatabases.data) {
                helpers.addResult(results, 3, `Unable to query Timestream Databases: ${helpers.addError(listDatabases)}`, region);
                return rcb();
            }

            if (!listDatabases.data.length) {
                helpers.addResult(results, 0, 'No Timestream Databases found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let database of listDatabases.data) {
                if (!database.Arn) continue;

                let resource = database.Arn;

                if (database.KmsKeyId) {
                    var kmsKeyId = database.KmsKeyId.split('/')[1] ? database.KmsKeyId.split('/')[1] : database.KmsKeyId;

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
                        `Timestream Databases is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `Timestream Databasesis encrypted with ${currentEncryptionLevelString} \
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