var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EFS Encryption Enabled',
    category: 'EFS',
    description: 'Ensures that EFS volumes are encrypted at rest',
    more_info: 'EFS offers data at rest encryption using keys managed through AWS Key Management Service (KMS).',
    link: 'https://aws.amazon.com/blogs/aws/new-encryption-at-rest-for-amazon-elastic-file-system-efs/',
    recommended_action: 'Encryption of data at rest can only be enabled during file system creation. Encryption of data in transit is configured when mounting your file system. 1. Backup your data in not encrypted efs 2. Recreate the EFS and select \'Enable encryption of data at rest\'',
    apis: ['EFS:describeFileSystems'],
    compliance: {
        hipaa: 'HIPAA requires that all data is encrypted, including data at rest. ' +
            'EFS is a HIPAA-compliant solution that provides automated encryption ' +
            'of EC2 storage data at rest.',
        pci: 'PCI requires proper encryption of cardholder data at rest. EFS ' +
            'encryption should be enabled for all volumes storing this type ' +
            'of data.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.efs, function(region, rcb) {
            var describeFileSystems = helpers.addSource(cache, source,
                ['efs', 'describeFileSystems', region]);

            if (!describeFileSystems) return rcb();

            if (describeFileSystems.err || !describeFileSystems.data) {
                helpers.addResult(
                    results, 3,
                    'Unable to query for EFS file systems: ' + helpers.addError(describeFileSystems), region);
                return rcb();
            }

            if(describeFileSystems.data.length === 0){
                helpers.addResult(results, 0, 'No EFS file systems present', region);
                return rcb();
            }

            var unencryptedEFS = [];

            describeFileSystems.data.forEach(function(efs){
                if (!efs.Encrypted){
                    unencryptedEFS.push(efs);
                }
            });

            if (unencryptedEFS.length > 20) {
                helpers.addResult(results, 2, 'More than 20 EFS systems are unencrypted', region);
            } else if (unencryptedEFS.length) {
                for (var u in unencryptedEFS) {
                    // ARN: arn:aws:elasticfilesystem:region:account-id:file-system/file-system-id
                    var arn = 'arn:aws:elasticfilesystem:' + region + ':' + unencryptedEFS[u].OwnerId + ':file-system/' + unencryptedEFS[u].FileSystemId;
                    helpers.addResult(results, 2, 'EFS: ' + unencryptedEFS[u].FileSystemId + ' is unencrypted', region, arn);
                }
            } else {
                helpers.addResult(results, 0, 'No unencrypted file systems found', region);
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
