var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Environment Data Encrypted',
    category: 'MWAA',
    domain: 'Compute',
    description: 'Ensure that AWS MWAA environment data is encrypted',
    more_info: 'Amazon MWAA encrypts data saved to persistent media with AWS-manager keys by default. ' +
        'Use customer-managed keys instead in order to gain more granular control over encryption/decryption process.',
    recommended_action: 'Create MWAA environments with customer-manager keys (CMKs)',
    link: 'https://docs.aws.amazon.com/mwaa/latest/userguide/encryption-at-rest.html',
    apis: ['MWAA:listEnvironments','MWAA:getEnvironment', 'KMS:describeKey', 'KMS:listKeys', 'STS:getCallerIdentity'],
    settings: {
        mwaa_environmentdata_desired_encryption_level: {
            name: 'MWAA Environment Data Deisred Encryption Level',
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
            desiredEncryptionLevelString: settings.mwaa_environmentdata_desired_encryption_level || this.settings.mwaa_environmentdata_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.mwaa, function(region, rcb){        
            var listEnvironments = helpers.addSource(cache, source,
                ['mwaa', 'listEnvironments', region]);

            if (!listEnvironments) return rcb();

            if (listEnvironments.err || !listEnvironments.data) {
                helpers.addResult(results, 3,
                    'Unable to query MWAA Environments: ' + helpers.addError(listEnvironments), region);
                return rcb();
            }

            if (!listEnvironments.data.length) {
                helpers.addResult(results, 0, 'No MWAA Environments found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);
              

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let environment of listEnvironments.data) {
                var resource = `arn:${awsOrGov}:airflow:${region}:${accountId}:environment/${environment}`;
               
                var getEnvironment = helpers.addSource(cache, source,
                    ['mwaa', 'getEnvironment', region, environment]);
                   

                if (!getEnvironment || getEnvironment.err || !getEnvironment.data || !getEnvironment.data.Environment) {
                    helpers.addResult(results, 3,
                        `Unable to get MWAA environment: ${helpers.addError(getEnvironment)}`,
                        region, resource);
                    continue;
                } 

                if (getEnvironment.data.Environment && getEnvironment.data.Environment.KmsKey) {
                    var KmsKey = getEnvironment.data.Environment.KmsKey;
                    var keyId = KmsKey.split('/')[1] ? KmsKey.split('/')[1] : KmsKey;

                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, keyId]);  

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, KmsKey);
                        continue;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                } else {
                    currentEncryptionLevel = 2; //awskms
                }

                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `MWAA Environment data is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `MWAA Environment data is encrypted with ${currentEncryptionLevelString} \
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
