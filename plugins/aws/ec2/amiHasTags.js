var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AMI Has Tags',
    category: 'EC2',
    domain: 'Compute',
    description: 'Ensure that AMIs have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://aws.amazon.com/about-aws/whats-new/2020/12/amazon-machine-images-support-tag-on-create-tag-based-access-control/',
    recommended_action: 'Modify AMI and add tags.',
    apis: ['EC2:describeImages'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        async.each(regions.ec2, function(region, rcb){
            var describeImages = helpers.addSource(cache, source,
                ['ec2', 'describeImages', region]);

            if (!describeImages) return rcb();

            if (describeImages.err || !describeImages.data) {
                helpers.addResult(results, 3,
                    'Unable to query for AMIs: ' + helpers.addError(describeImages), region);
                return rcb();
            }

            if (!describeImages.data.length) {
                helpers.addResult(results, 0, 'No AMIs found', region);
                return rcb();
            }

            for (var ami of describeImages.data) {
                if (!ami.ImageId) continue;
                
                const arn ='arn:' + awsOrGov + ':ec2:' + region + '::image/' + ami.ImageId;
                if (!ami.Tags || !ami.Tags.length) {
                    helpers.addResult(results, 2, 'AMI does not have any tags', region, arn);
                } else {
                    helpers.addResult(results, 0, 'AMI has tags', region, arn);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
