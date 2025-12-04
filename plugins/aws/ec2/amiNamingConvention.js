var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AMI Naming Conventions',
    category: 'EC2',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensure that Amazon Machine Images (AMIs) follow organizational naming conventions for tagging',
    more_info: 'AMIs should follow a consistent naming convention using the Name tag to identify their purpose, environment, and region. This helps prevent accidental use of incorrect images, reduces operational errors, and improves resource management. Without proper naming conventions, teams may deploy instances with outdated or inappropriate AMIs, leading to security vulnerabilities or configuration issues.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html',
    recommended_action: 'Update AMI Name tags to follow organizational naming conventions.',
    apis: ['EC2:describeImages'],
    settings: {
        ami_naming_pattern: {
            name: 'AMI Naming Pattern',
            description: 'A regex pattern to validate AMI Name tag values. Default: ^ami-(ue1|uw1|uw2|ew1|ec1|an1|an2|as1|as2|se1)-(d|t|s|p)-([a-z0-9\\-]+)$',
            regex: '^.*$',
            default: '^ami-(ue1|uw1|uw2|ew1|ec1|an1|an2|as1|as2|se1)-(d|t|s|p)-([a-z0-9\\-]+)$'
        }
    },
    realtime_triggers: ['ec2:CreateImage', 'ec2:CreateTags', 'ec2:DeleteTags', 'ec2:DeregisterImage'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        var config = {
            ami_naming_pattern: settings.ami_naming_pattern || this.settings.ami_naming_pattern.default
        };

        var namingPattern = new RegExp(config.ami_naming_pattern);

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
                
                const arn = 'arn:' + awsOrGov + ':ec2:' + region + '::image/' + ami.ImageId;

                if (!ami.Tags || !ami.Tags.length) {
                    helpers.addResult(results, 2,
                        'AMI does not have a name tag', region, arn);
                    continue;
                }

                var nameTag = ami.Tags.find(tag => tag.Key === 'Name');

                if (!nameTag || !nameTag.Value) {
                    helpers.addResult(results, 2,
                        'AMI does not have a name tag', region, arn);
                } else if (!namingPattern.test(nameTag.Value)) {
                    helpers.addResult(results, 2,
                        `AMI Name tag "${nameTag.Value}" does not follow organizational naming convention`, region, arn);
                } else {
                    helpers.addResult(results, 0,
                        `AMI Name tag "${nameTag.Value}" follows organizational naming convention`, region, arn);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};

