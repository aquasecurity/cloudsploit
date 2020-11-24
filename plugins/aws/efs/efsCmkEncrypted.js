var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AWS EFS CMK Encrypted',
    category: 'EFS',
    description: 'Ensure EFS file systems are encrypted using Customer Master Keys (CMKs).',
    more_info: 'EFS file systems should use KMS Customer Master Keys (CMKs) instead of AWS managed keys for encryption in order to have full control over data encryption and decryption.',
    link: 'https://docs.aws.amazon.com/efs/latest/ug/encryption-at-rest.html',
    recommended_action: 'Encryption at rest key can only be configured during file system creation. Encryption of data in transit is configured when mounting your file system. 1. Backup your data in not encrypted efs 2. Recreate the EFS and use KMS CMK for encryption of data at rest.',
    apis: ['EFS:describeFileSystems', 'KMS:listAliases'],
    settings: {
        cmk_unencrypted_threshold: {
            name: 'Threshold for EFS CMK Unencrypted Individual Reporting.',
            description: 'Sets the value where EFS CMK unencryption reporting becomes aggregated once breached.',
            regex: '^[0-9]*$',
            default: 20
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var cmk_unencrypted_threshold = settings.cmk_unencrypted_threshold || this.settings.cmk_unencrypted_threshold.default; 

        async.each(regions.efs, function(region, rcb) {
            var describeFileSystems = helpers.addSource(cache, source,
                ['efs', 'describeFileSystems', region]);

            if (!describeFileSystems) return rcb();

            if (describeFileSystems.err || !describeFileSystems.data) {
                helpers.addResult(
                    results, 3,
                    `Unable to query for EFS file systems: ${helpers.addError(describeFileSystems)}`, region);
                return rcb();
            }

            if(!describeFileSystems.data.length){
                helpers.addResult(results, 0, 'No EFS file systems found', region);
                return rcb();
            }

            var listAliases = helpers.addSource(cache, source,
                ['kms', 'listAliases', region]);

            if (!listAliases || listAliases.err || !listAliases.data) {
                helpers.addResult(results, 3,
                    `Unable to query for KMS aliases: ${helpers.addError(listAliases)}`,
                    region);
                return rcb();
            }

            var aliasId;
            var kmsAliases = {};
            var cmkUnencryptedEFS = [];
            var danglingKeys = [];

            listAliases.data.forEach(function(alias){
                aliasId = alias.AliasArn.replace(/:alias\/.*/, ':key/' + alias.TargetKeyId);
                kmsAliases[aliasId] = alias.AliasName;
            });

            describeFileSystems.data.forEach(function(efs){
                if (efs.Encrypted && efs.KmsKeyId){
                    if (kmsAliases[efs.KmsKeyId] && kmsAliases[efs.KmsKeyId] === 'alias/aws/elasticfilesystem') {
                        cmkUnencryptedEFS.push(efs);
                    } else if (!kmsAliases[efs.KmsKeyId]) {
                        danglingKeys.push(efs);
                    }
                }
            });

            if (cmkUnencryptedEFS.length > cmk_unencrypted_threshold) {
                helpers.addResult(results, 2, `More than ${cmk_unencrypted_threshold} EFS systems are not using CMK for encryption`, region);
            } else if (cmkUnencryptedEFS.length) {
                for (let u in cmkUnencryptedEFS) {
                    let resource = cmkUnencryptedEFS[u].FileSystemArn;
                    helpers.addResult(results, 2, `EFS "${cmkUnencryptedEFS[u].FileSystemId}" is not CMK encrypted`, region, resource);
                }
            } else {
                helpers.addResult(results, 0, 'No AWS managed key encrypted file systems found', region);
            }

            if (danglingKeys.length > cmk_unencrypted_threshold) {
                helpers.addResult(results, 2, `More than ${cmk_unencrypted_threshold} EFS systems are referencing deleted KMS keys`, region);
            } else if (danglingKeys.length) {
                for (let u in danglingKeys) {
                    let resource = danglingKeys[u].FileSystemArn;
                    helpers.addResult(results, 2, `EFS "${danglingKeys[u].FileSystemId}" is referencing deleted KMS key`, region, resource);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
