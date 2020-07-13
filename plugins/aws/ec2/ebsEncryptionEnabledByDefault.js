var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EBS Encryption Enabled By Default',
    category: 'EC2',
    description: 'Ensure the setting for Encryption by default is enabled',
    more_info: 'An AWS account may be configured such that, for a particular region(s), it will be mandatory that new EBS volumes and snapshot copies are encrypted.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default',
    recommended_action: 'Enable EBS Encryption by Default',
    apis: ['EC2:getEbsEncryptionByDefault'],


    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ec2, function(region, rcb){
            var getEbsEncryptionByDefault = helpers.addSource(cache, source,
                ['ec2', 'getEbsEncryptionByDefault', region]);
            if (!getEbsEncryptionByDefault) return rcb();

            if (getEbsEncryptionByDefault.err) {
                helpers.addResult(results, 3,
                    'Unable to query for ebs encryption by default status: ' + helpers.addError(getEbsEncryptionByDefault), region);
                return rcb();
            }

            if (getEbsEncryptionByDefault.data) {
                helpers.addResult(results, 0,
                    'EBS encryption by default is enabled', region);
                return rcb();
            }

            if (!getEbsEncryptionByDefault.data) {
                helpers.addResult(results, 2,
                    'EBS encryption by default is not enabled', region);
                return rcb();
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
