var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Ledger Encrypted',
    category: 'QLDB',
    domain: 'Databases',
    description: 'Ensure that AWS QLDB ledger is encrypted using desired encryption level',
    more_info: 'QLDB encryption at rest provides enhanced security by encrypting all ledger data at rest using encryption keys in AWS Key Management Service (AWS KMS).' +
               'Use customer-managed keys (CMKs) instead in order to gain more granular control over encryption/decryption process.',
    recommended_action: 'Create QLDB ledger with customer-manager keys (CMKs)',
    link: 'https://docs.aws.amazon.com/qldb/latest/developerguide/encryption-at-rest.html',
    apis: ['QLDB:listLedgers','QLDB:describeLedger', 'KMS:describeKey', 'KMS:listKeys', 'STS:getCallerIdentity'],
    settings: {
        qldb_ledger_desired_encryption_level: {
            name: 'QLDB ledger desired encryption level',
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
            desiredEncryptionLevelString: settings.qldb_ledger_desired_encryption_level || this.settings.qldb_ledger_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.qldb, function(region, rcb){        
            var listLedgers = helpers.addSource(cache, source,
                ['qldb', 'listLedgers', region]);

            if (!listLedgers) return rcb();

            if (listLedgers.err || !listLedgers.data) {
                helpers.addResult(results, 3,
                    'Unable to query Ledgers: ' + helpers.addError(listLedgers), region);
                return rcb();
            }

            if (!listLedgers.data.length) {
                helpers.addResult(results, 0, 'No Ledgers found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let ledger of listLedgers.data) {
                if (!ledger.Name) continue;

                let resource = `arn:${awsOrGov}:qldb:${region}:${accountId}:ledger/${ledger.Name}`;

                var describeLedger = helpers.addSource(cache, source,
                    ['qldb', 'describeLedger', region, ledger.Name]);

                if (!describeLedger || describeLedger.err || !describeLedger.data ) {
                    helpers.addResult(results, 3,
                        `Unable to get Ledgers description: ${helpers.addError(describeLedger)}`,
                        region, resource);
                    continue;
                } 

                if (describeLedger.data.EncryptionDescription &&
                    describeLedger.data.EncryptionDescription.KmsKeyArn) {

                    var kmsKeyArn = describeLedger.data.EncryptionDescription.KmsKeyArn;
                    var keyId = kmsKeyArn.split('/')[1] ? kmsKeyArn.split('/')[1] : kmsKeyArn;

                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, keyId]);

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, kmsKeyArn);
                        continue;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                } else {
                    currentEncryptionLevel = 2; //awskms
                }

                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `QLDB ledger is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `QLDB ledger is encrypted with ${currentEncryptionLevelString} \
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
