var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EBS Encryption Enabled',
    category: 'EC2',
    description: 'Ensures EBS volumes are encrypted at rest',
    more_info: 'EBS volumes should have at-rest encryption enabled through AWS using KMS. If the volume is used for a root volume, the instance must be launched from an AMI that has been encrypted as well.',
    link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html',
    recommended_action: 'Enable encryption for EBS volumes.',
    apis: ['EC2:describeVolumes'],
    compliance: {
        hipaa: 'HIPAA requires that all data is encrypted, including data at rest. ' +
                'EBS is a HIPAA-compliant solution that provides automated encryption ' +
                'of EC2 instance data at rest.',
        pci: 'PCI requires proper encryption of cardholder data at rest. EBS ' +
             'encryption should be enabled for all volumes storing this type ' +
             'of data.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ec2, function(region, rcb){
            var describeVolumes = helpers.addSource(cache, source,
                ['ec2', 'describeVolumes', region]);

            if (!describeVolumes) return rcb();

            if (describeVolumes.err || !describeVolumes.data) {
                helpers.addResult(results, 3,
                    'Unable to query for EBS volumes: ' + helpers.addError(describeVolumes), region);
                return rcb();
            }

            if (!describeVolumes.data.length) {
                helpers.addResult(results, 0, 'No EBS volumes present', region);
                return rcb();
            }

            var unencryptedVolumes = [];

            describeVolumes.data.forEach(function(Volume){
                if (!Volume.Encrypted){
                    unencryptedVolumes.push(Volume.VolumeId);
                }
            });

            if (unencryptedVolumes.length > 20) {
                helpers.addResult(results, 2, 'More than 20 EBS volumes are unencrypted', region);
            } else if (unencryptedVolumes.length) {
                for (u in unencryptedVolumes) {
                    helpers.addResult(results, 2, 'EBS volume is unencrypted', region, unencryptedVolumes[u]);
                }
            } else {
                helpers.addResult(results, 0, 'No unencrypted volumes found', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
