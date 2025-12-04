var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Old Amazon Machine Images',
    category: 'EC2',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensure that Amazon Machine Images (AMIs) are not older than a specified number of days.',
    more_info: 'Amazon Machine Images that are too old may contain outdated software, security vulnerabilities, or deprecated configurations. Regularly updating and replacing old AMIs helps maintain security and operational efficiency.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html',
    recommended_action: 'Review and replace AMIs that are older than the specified threshold with newer versions.',
    apis: ['EC2:describeImages'],
    settings: {
        ami_age_fail: {
            name: 'AMI Age Fail',
            description: 'Return a failing result when AMI exceeds this number of days',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 90
        }
    },
    realtime_triggers: ['ec2:CreateImage', 'ec2:DeregisterImage'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        var config = {
            ami_age_fail: parseInt(settings.ami_age_fail || this.settings.ami_age_fail.default),
        };

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

            var now = new Date();

            for (var ami of describeImages.data) {
                if (!ami.ImageId) continue;
                
                const arn = 'arn:' + awsOrGov + ':ec2:' + region + '::image/' + ami.ImageId;

                if (!ami.CreationDate) {
                    helpers.addResult(results, 3,
                        'AMI does not have a creation date', region, arn);
                    continue;
                }

                var creationDate = new Date(ami.CreationDate);
                var difference = helpers.daysBetween(creationDate, now);

                if (difference > config.ami_age_fail) {
                    helpers.addResult(results, 2,
                        `AMI is ${Math.floor(difference)} days old`, region, arn);
                } else {
                    helpers.addResult(results, 0,
                        `AMI is ${Math.floor(difference)} days old`, region, arn);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};

