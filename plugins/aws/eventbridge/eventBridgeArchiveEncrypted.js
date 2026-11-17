var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EventBridge Archive Encrypted',
    category: 'EventBridge',
    domain: 'Management and Governance',
    severity: 'High',
    description: 'Ensures that EventBridge archives are encrypted using a KMS key of the desired encryption level.',
    more_info: 'An EventBridge archive stores the events of an event bus so that they can be replayed later. These events can contain sensitive data. ' +
        'Archives that are not configured with a KMS key are encrypted with an AWS owned key, which gives no control over the key policy, rotation or access auditing. ' +
        'Use a customer managed key to control who can decrypt the archived events.',
    link: 'https://docs.aws.amazon.com/eventbridge/latest/userguide/encryption-archives.html',
    recommended_action: 'Configure every EventBridge archive to use a KMS key of the desired encryption level.',
    apis: ['EventBridge:listArchives', 'EventBridge:describeArchive', 'KMS:listKeys', 'KMS:describeKey', 'KMS:listAliases'],
    settings: {
        eventbridge_archive_desired_encryption_level: {
            name: 'EventBridge Archive Target Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk'
        }
    },
    realtime_triggers: ['eventbridge:CreateArchive', 'eventbridge:UpdateArchive', 'eventbridge:DeleteArchive'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            desiredEncryptionLevelString: settings.eventbridge_archive_desired_encryption_level || this.settings.eventbridge_archive_desired_encryption_level.default
        };
        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);

        async.each(regions.eventbridge, function(region, rcb) {
            var listArchives = helpers.addSource(cache, source, ['eventbridge', 'listArchives', region]);

            if (!listArchives) return rcb();

            if (listArchives.err || !listArchives.data) {
                helpers.addResult(results, 3,
                    'Unable to query for EventBridge archives: ' + helpers.addError(listArchives), region);
                return rcb();
            }

            if (!listArchives.data.length) {
                helpers.addResult(results, 0, 'No EventBridge archives found', region);
                return rcb();
            }

            var listAliases = helpers.addSource(cache, source, ['kms', 'listAliases', region]);
            var kmsAliasArnMap = {};
            if (listAliases && !listAliases.err && listAliases.data) {
                listAliases.data.forEach(function(alias) {
                    if (!alias.TargetKeyId) return;
                    kmsAliasArnMap[alias.AliasName] = alias.AliasArn.replace(/:alias\/.*/, ':key/' + alias.TargetKeyId);
                });
            }

            listArchives.data.forEach(function(archive) {
                // arn:aws:events:region:account-id:archive/archive-name
                var resource = archive.ArchiveArn || archive.ArchiveName;

                var describeArchive = helpers.addSource(cache, source,
                    ['eventbridge', 'describeArchive', region, archive.ArchiveName]);

                if (!describeArchive || describeArchive.err || !describeArchive.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for EventBridge archive: ' + helpers.addError(describeArchive), region, resource);
                    return;
                }

                resource = describeArchive.data.ArchiveArn || resource;
                var keyIdentifier = describeArchive.data.KmsKeyIdentifier;

                if (!keyIdentifier) {
                    helpers.addResult(results, 2,
                        'EventBridge archive is not encrypted with a KMS key', region, resource);
                    return;
                }

                // The identifier is a key id, key ARN, alias name or alias ARN
                var aliasName = keyIdentifier.indexOf('alias/') > -1 ? 'alias/' + keyIdentifier.split('alias/')[1] : null;
                var keyArn = aliasName ? (kmsAliasArnMap[aliasName] || aliasName) : keyIdentifier;
                var keyId = keyArn.indexOf('key/') > -1 ? keyArn.split('key/')[1] : keyArn;

                var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, keyId]);

                if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                    helpers.addResult(results, 3,
                        'Unable to query KMS key: ' + helpers.addError(describeKey), region, resource);
                    return;
                }

                var currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `EventBridge archive is encrypted with ${currentEncryptionLevelString} which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `EventBridge archive is encrypted with ${currentEncryptionLevelString} which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
