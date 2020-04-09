var async = require('async');
var helpers = require('../../../helpers/aws');

const encryptionLevelMap = {
    sse: 1,
    awskms: 2,
    awscmk: 3,
    externalcmk: 4,
    cloudhsm: 5
};

function getEncryptionLevel(kmsKey) {
    return kmsKey.Origin === 'AWS_CLOUDHSM' ? 'cloudhsm' :
           kmsKey.Origin === 'EXTERNAL' ? 'externalcmk' :
           kmsKey.KeyManager === 'CUSTOMER' ? 'awscmk' : 'awskms'
}

module.exports = {
    title: 'SSM Encrypted Parameters',
    category: 'SSM',
    description: 'Ensures SSM Parameters are encrypted',
    more_info: 'SSM Parameters should be encrypted. This allows their values to be used by approved systems, while restricting access to other users of the account.',
    link: 'https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-about.html#sysman-paramstore-securestring',
    recommended_action: 'Recreate unencrypted SSM Parameters with Type set to SecureString.',
    apis: ['SSM:describeParameters', 'STS:getCallerIdentity', 'KMS:listAliases', 'KMS:listKeys', 'KMS:describeKey'],
    compliance: {
        hipaa: 'HIPAA requires that all data is encrypted, including data at rest',
        pci: 'PCI requires proper encryption of cardholder data at rest. SSM ' +
             'encryption should be enabled for all parameters storing this type ' +
             'of data.'
    },
    settings: {
        ssm_encryption_level: {
            name: 'SSM Minimum Encryption Level',
            description: 'In order (lowest to highest) \
                awskms=AWS-managed KMS; \
                awscmk=Customer managed KMS; \
                externalcmk=Customer managed externally sourced KMS; \
                cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awskms',
        },
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var desiredEncryptionLevelString = settings.ssm_encryption_level || this.settings.ssm_encryption_level.default
        if(!desiredEncryptionLevelString.match(this.settings.ssm_encryption_level.regex)) {
            helpers.addResult(results, 3, 'Settings misconfigured for SSM Encryption Level.');
            return callback(null, results, source);
        }

        var desiredEncryptionLevel = encryptionLevelMap[desiredEncryptionLevelString]

        var regions = helpers.regions(settings);
        var defaultRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', defaultRegion, 'data']);

        async.each(regions.ssm, function(region, rcb) {
            var describeParameters = helpers.addSource(cache, source, ['ssm', 'describeParameters', region]);

            if (!describeParameters) return rcb();

            if (describeParameters.err || !describeParameters.data) {
                helpers.addResult(results, 3, `Unable to query for Parameters: ${helpers.addError(describeParameters)}`, region);
                return rcb();
            }

            if (!describeParameters.data.length) {
                helpers.addResult(results, 0, 'No Parameters present', region);
                return rcb();
            }

            for (let parameter of describeParameters.data) {
                var parameterName = parameter.Name.charAt(0) === '/' ? parameter.Name.substr(1) : parameter.Name;
                var arn = `arn:aws:ssm:${region}:${accountId}:parameter/${parameterName}`;

                if (parameter.Type != 'SecureString') {
                    helpers.addResult(results, 2, 'Non-SecureString Parameters present', region, arn);
                    continue;
                }

                var keyId;
                if(parameter.KeyId.includes('alias')) {
                    var aliases = helpers.addSource(cache, source, ['kms', 'listAliases', region]);
                    if (!aliases || aliases.err || !aliases.data) {
                        helpers.addResult(results, 3, `Unable to query for Aliases: ${helpers.addError(aliases)}`, region);
                        continue;
                    }
                    if (!aliases.data.length) {
                        helpers.addResult(results, 3, 'No Aliases present, however one is required.', region);
                        continue;
                    }
                    alias = aliases.data.find(a => a.AliasName === parameter.KeyId)
                    if (!alias) {
                        helpers.addResult(results, 3, 'Unable to locate alias: ' + parameter.KeyId, region);
                        continue;
                    } else {
                        keyId = alias.TargetKeyId
                    }
                } else {
                    keyId = parameter.KeyId.split('/')[1]
                }

                var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, keyId]);

                if(!describeKey) {
                    helpers.addResult(results, 3, 'Unable to locate KMS key for describeKey: ' + keyId, region);
                    continue;
                }
                if (describeKey.err || !describeKey.data) {
                    helpers.addResult(results, 3, 'Unable to query for KMS Key: ' + helpers.addError(describeKey), region);
                    continue;
                }

                currentEncryptionLevelString = getEncryptionLevel(describeKey.data.KeyMetadata)
                currentEncryptionLevel = encryptionLevelMap[currentEncryptionLevelString]

                if (currentEncryptionLevel < desiredEncryptionLevel) {
                    helpers.addResult(results, 1, `SSM Param is encrypted to ${currentEncryptionLevelString}, which is lower than the desired ${desiredEncryptionLevelString} level.`, region, arn);
                } else {
                    helpers.addResult(results, 0, `SSM Param is encrypted to a minimum of ${desiredEncryptionLevelString}`, region, arn);
                }
                continue;
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
