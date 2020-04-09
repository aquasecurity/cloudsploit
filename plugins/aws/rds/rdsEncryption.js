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
    title: 'RDS Encryption Enabled',
    category: 'RDS',
    description: 'Ensures at-rest encryption with Customer Key is setup for RDS instances containing sensitive data.',
    more_info: 'AWS provides at-rest encryption for RDS instances which should be enabled to ensure the integrity of data stored within the databases.',
    link: 'http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html',
    recommended_action: 'RDS does not currently allow modifications to encryption after the instance has been launched, so a new instance will need to be created with encryption enabled.',
    apis: ['RDS:describeDBInstances', 'kms:describeKey'],
    compliance: {
        hipaa: 'All data in HIPAA environments must be encrypted, including ' +
                'data at rest. RDS encryption ensures that this HIPAA control ' +
                'is implemented by providing KMS-backed encryption for all RDS ' +
                'data.',
        pci: 'PCI requires proper encryption of cardholder data at rest. RDS ' +
             'encryption should be enabled for all instances storing this type ' +
             'of data.'
    },
    settings: {
        rds_encryption_level: {
            name: 'RDS Minimum Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awskms',
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var desiredEncryptionLevelString = settings.rds_encryption_level || this.settings.rds_encryption_level.default
        if(!desiredEncryptionLevelString.match(this.settings.rds_encryption_level.regex)) {
            helpers.addResult(results, 3, 'Settings misconfigured for RDS Encryption Level.');
            return callback(null, results, source);
        }

        var desiredEncryptionLevel = encryptionLevelMap[desiredEncryptionLevelString]
        var currentEncryptionLevelString, currentEncryptionLevel
        var regions = helpers.regions(settings);
        async.each(regions.rds, function(region, rcb){
            var describeDBInstances = helpers.addSource(cache, source, ['rds', 'describeDBInstances', region]);
            if (!describeDBInstances) return rcb();

            if (describeDBInstances.err || !describeDBInstances.data) {
                helpers.addResult(results, 3, 'Unable to query for RDS instances: ' + helpers.addError(describeDBInstances), region);
                return rcb();
            }

            if (!describeDBInstances.data.length) {
                helpers.addResult(results, 0, 'No RDS instances found', region);
                return rcb();
            }

            async.each(describeDBInstances.data, function(db, dcb) {
                // For resource, attempt to use the endpoint address (more specific) but fallback to the instance identifier
                var dbResource = db.DBInstanceArn;
                if (db.StorageEncrypted) {
                    var keyId = db.KmsKeyId.split("/")[1];
                    var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, keyId]);
                    if(!describeKey) {
                        helpers.addResult(results, 3, 'Unable locate KMS key for describeKey: ' + keyId, region);
                        return dcb();
                    }
                    if (describeKey.err || !describeKey.data) {
                        helpers.addResult(results, 3, 'Unable to query for KMS Key: ' + helpers.addError(describeKey), region);
                        return dcb();
                    }

                    currentEncryptionLevelString = getEncryptionLevel(describeKey.data.KeyMetadata)
                    currentEncryptionLevel = encryptionLevelMap[currentEncryptionLevelString]

                    if (currentEncryptionLevel < desiredEncryptionLevel) {
                        helpers.addResult(results, 1, `RDS Storage is encrypted to ${currentEncryptionLevelString}, which is lower than the desired ${desiredEncryptionLevelString} level.`, region, dbResource);
                    } else {
                        helpers.addResult(results, 0, `RDS Storage is encrypted to a minimum of ${desiredEncryptionLevelString}`, region, dbResource);
                    }
                } else {
                    helpers.addResult(results, 2, 'Encryption at rest is not enabled.', region, dbResource);
                }
                return dcb()
            }, rcb);
        }, function(){
            callback(null, results, source);
        });
    }
};
