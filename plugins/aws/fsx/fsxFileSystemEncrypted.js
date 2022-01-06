var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'FSx File System Encrypted',
    category: 'FSx',
    domain: 'Storage',
    description: 'Ensure that Amazon FSx for Windows File Server file systems are encrypted using desired KMS encryption level.',
    more_info: 'If your organization is subject to corporate or regulatory policies that require encryption of data and metadata at rest, AWS recommends creating encrypted file systems.',
    recommended_action: 'Enable encryption for file systems created under Amazon FSx for Windows File Server',
    link: 'https://docs.aws.amazon.com/fsx/latest/WindowsGuide/encryption.html',
    apis: ['FSx:describeFileSystems', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        fsx_file_systems_encryption_level: {
            name: 'FSx File Systems Target Encryption Level',
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
            desiredEncryptionLevelString: settings.fsx_file_systems_encryption_level || this.settings.fsx_file_systems_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.connect, function(region, rcb){
            var listFileSystems = helpers.addSource(cache, source,
                ['fsx', 'describeFileSystems', region]);

            if (!listFileSystems) return rcb();

            if (listFileSystems.err || !listFileSystems.data) {
                helpers.addResult(results, 3,
                    `Unable to query FSx file systems: ${helpers.addError(listFileSystems)}`, region);
                return rcb();
            }

            if (!listFileSystems.data.length) {
                helpers.addResult(results, 0, 'No FSx file systems found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let fileSystem of listFileSystems.data) {
                if (fileSystem.FileSystemType && fileSystem.FileSystemType.toLowerCase() !== 'windows') {
                    continue;
                }

                var resource = fileSystem.Arn;

                if (fileSystem.KmsKeyId) {
                    let encryptionKey = fileSystem.KmsKeyId;
                    var keyId = encryptionKey.split('/')[1] ? encryptionKey.split('/')[1] : encryptionKey;

                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, keyId]);

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, encryptionKey);
                        continue;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                } else currentEncryptionLevel = 2; //awskms

                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `FSx file system is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `FSx file system is encrypted with ${currentEncryptionLevelString} \
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
