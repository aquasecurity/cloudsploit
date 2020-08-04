var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EC2 Instance Key Based Login',
    category: 'EC2',
    description: 'Ensures EC2 instances have associated keys for password-less SSH login',
    more_info: 'AWS allows EC2 instances to be launched with a specified PEM key for SSH login which should be used instead of user and password login.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html',
    recommended_action: 'Ensure each EC2 instance has an associated SSH key and disable password login.',
    apis: ['EC2:describeInstances'],
    settings: {
        instance_keypair_threshold: {
            name: 'Instance Key Pair Threshold',
            description: 'If more than this number of instances are missing an ssh key pair, results will be collapsed into a single result to avoid excessive result counts. Max is 299.',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 10
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            instance_keypair_threshold: settings.instance_keypair_threshold || this.settings.instance_keypair_threshold.default
        };

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ec2, function(region, rcb){
            var describeInstances = helpers.addSource(cache, source,
                ['ec2', 'describeInstances', region]);

            if (!describeInstances) return rcb();

            if (describeInstances.err || !describeInstances.data) {
                helpers.addResult(results, 3,
                    'Unable to query for instances: ' + helpers.addError(describeInstances), region);
                return rcb();
            }

            if (!describeInstances.data.length) {
                helpers.addResult(results, 0, 'No instances found', region);
                return rcb();
            }

            var found = 0;

            for (var i in describeInstances.data) {
                var accountId = describeInstances.data[i].OwnerId;

                for (var j in describeInstances.data[i].Instances) {
                    var instance = describeInstances.data[i].Instances[j];

                    if (!instance.KeyName) {
                        found += 1;
                        helpers.addResult(results, 2,
                            'Instance does not have associated keys for password-less SSH login', region,
                            'arn:aws:ec2:' + region + ':' + accountId + ':instance/' +
                            instance.InstanceId, custom);
                    }
                }
            }

            // Too many results to print individually
            if (found > config.instance_keypair_threshold) {
                results = [];

                helpers.addResult(results, 2,
                    'Over ' + config.instance_keypair_threshold + ' EC2 instances do not have associated keys for password-less SSH login', region, null, custom);
            }

            if (!found) {
                helpers.addResult(results, 0,
                    'All ' + describeInstances.data.length + ' instances have associated keys for password-less SSH login', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
