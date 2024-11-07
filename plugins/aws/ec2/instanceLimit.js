var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Instance Limit',
    category: 'EC2',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Determine if the number of EC2 instances is close to the AWS per-account limit',
    more_info: 'AWS limits accounts to certain numbers of resources. Exceeding those limits could prevent resources from launching.',
    link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html#using-instance-addressing-limit',
    recommended_action: 'Contact AWS support to increase the number of instances available',
    apis: ['EC2:describeInstances'],
    settings: {
        instance_limit_percentage_fail: {
            name: 'Instance Limit Percentage Fail',
            description: 'Return a failing result when utilized instances equals or exceeds this percentage',
            regex: '^(100|[1-9][0-9]?)$',
            default: 90
        },
        instance_limit_percentage_warn: {
            name: 'Instance Limit Percentage Warn',
            description: 'Return a warning result when utilized instances equals or exceeds this percentage',
            regex: '^(100|[1-9][0-9]?)$',
            default: 75
        },
        max_instance_count: {
            name: 'Max Instance Count',
            description: 'Check for the max number of utilized instance in a region',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
    },
    realtime_triggers: ['ec2:RunInstances', 'ec2:TerminateInstances'],

    run: function(cache, settings, callback) {
        var config = {
            instance_limit_percentage_fail: settings.instance_limit_percentage_fail || this.settings.instance_limit_percentage_fail.default,
            instance_limit_percentage_warn: settings.instance_limit_percentage_warn || this.settings.instance_limit_percentage_warn.default,
            max_instance_count: settings.max_instance_count || this.settings.max_instance_count.default
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

            var instanceCount = 0;

            if (!describeInstances.data.length) {
                helpers.addResult(results, 0, 'No instances found', region);
                return rcb();
            } else {
                for (var i in describeInstances.data) {
                    for (var j in describeInstances.data[i].Instances) {
                        var instance = describeInstances.data[i].Instances[j];

                        if (instance.State.Name === 'running') {
                            instanceCount +=1;
                        }
                    }
                }
            }

            var percentage = Math.ceil((instanceCount / config.max_instance_count)*100);
            var returnMsg = 'Account contains ' + instanceCount + ' of ' + config.max_instance_count + ' (' + percentage + '%) available instances';

            if (percentage >= config.instance_limit_percentage_fail) {
                helpers.addResult(results, 2, returnMsg, region, null, custom);
            } else if (percentage >= config.instance_limit_percentage_warn) {
                helpers.addResult(results, 1, returnMsg, region, null, custom);
            } else {
                helpers.addResult(results, 0, returnMsg, region, null, custom);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};