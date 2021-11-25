var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: ' Timestream Database Encrypted',
    category: 'Timestream',
    domain: 'Databases',
    description: 'Ensure that AWS Timestream databases are encrypted with KMS Customer Master Keys (CMKs) instead of AWS managed-keys.',
    more_info: 'Timestream encryption at rest provides enhanced security by encrypting all your data at rest using encryption keys. ' +
        'This functionality helps reduce the operational burden and complexity involved in protecting sensitive data. ' +
        'With encryption at rest using customer-managed keys, you can build security-sensitive applications that meet strict encryption compliance and regulatory requirements. ',
    recommended_action: 'Modify Trimestream database encryption configuration to use desired encryption key',
    link: 'https://docs.aws.amazon.com/timestream/latest/developerguide/EncryptionAtRest.html',
    apis: ['TimestreamWrite:listDatabases', 'KMS:describeKey', 'KMS:listKeys'],
    settings: {
        timestream_databases_desired_encryption_level: {
            name: 'Timestream Database Target Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            desiredEncryptionLevelString: settings.timestream_databases_desired_encryption_level || this.settings.timestream_databases_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.timestreamwrite, function(region, rcb){
            var listDatabases = helpers.addSource(cache, source,
                ['timestreamwrite', 'listDatabases', region]);
               
            if (!listDatabases) return rcb();

            if (listDatabases.err || !listDatabases.data) {
                helpers.addResult(results, 3, `Unable to query Timestream databases: ${helpers.addError(listDatabases)}`, region);
                return rcb();
            }

            if (!listDatabases.data.length) {
                helpers.addResult(results, 0, 'No Timestream databases found', region);
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
                            region, database.KmsKeyId);
                        continue;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                } else {
                    currentEncryptionLevel = 2; //awskms
                }

                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `Timestream database is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `Timestream database is encrypted with ${currentEncryptionLevelString} \
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
