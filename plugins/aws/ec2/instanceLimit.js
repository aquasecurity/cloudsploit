var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Instance Limit',
    category: 'EC2',
    description: 'Determine if the number of vCPUs used by running On-Demand EC2 instances is close to the AWS per-region limit.',
    more_info: 'AWS limits accounts to certain numbers of resources. Exceeding those limits could prevent resources from launching.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-on-demand-instances.html',
    recommended_action: 'Contact AWS support to increase the number of EC2 instance vCPUs available',
    apis: ['EC2:describeInstances', 'ServiceQuotas:listServiceQuotas'],
    settings: {
        instance_limit_percentage_fail: {
            name: 'Instance Limit Percentage Fail',
            description: 'Return a failing result when utilized EC2 instance vCPUs equals or exceeds this percentage',
            regex: '^(100|[1-9][0-9]?)$',
            default: 90
        },
        instance_limit_percentage_warn: {
            name: 'Instance Limit Percentage Warn',
            description: 'Return a warning result when utilized EC2 instance vCPUs equals or exceeds this percentage',
            regex: '^(100|[1-9][0-9]?)$',
            default: 75
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            instance_limit_percentage_fail: settings.instance_limit_percentage_fail || this.settings.instance_limit_percentage_fail.default,
            instance_limit_percentage_warn: settings.instance_limit_percentage_warn || this.settings.instance_limit_percentage_warn.default
        };

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.servicequotas, function(region, rcb){
            var listServiceQuotas = helpers.addSource(cache, source,
                ['servicequotas', 'listServiceQuotas', region]);
                
            if (!listServiceQuotas) return rcb();

            if (listServiceQuotas.err || !listServiceQuotas.data) {
                helpers.addResult(results, 3,
                    'Unable to list EC2 service quotas: ' + helpers.addError(listServiceQuotas), region);
                return rcb();
            }

            let vCPUsQuota = listServiceQuotas.data.find(quota => quota.QuotaCode == 'L-1216C47A');
            let vCPUsLimit = vCPUsQuota.Value ? vCPUsQuota.Value : 20;

            var describeInstances = helpers.addSource(cache, source,
                ['ec2', 'describeInstances', region]);

            if (!describeInstances) return rcb();

            if (describeInstances.err || !describeInstances.data) {
                helpers.addResult(results, 3,
                    'Unable to query for instances: ' + helpers.addError(describeInstances), region);
                return rcb();
            }

            var ec2vCPUs = 0;

            if (!describeInstances.data.length) {
                helpers.addResult(results, 0, 'No instances found', region);
                return rcb();
            } else {
                for (var instances in describeInstances.data){
                    for (var instance of describeInstances.data[instances].Instances){
                        if (instance.State && instance.State.Name && instance.State.Name.toUpperCase() == 'RUNNING' &&
                            instance.CpuOptions && instance.CpuOptions.CoreCount && instance.CpuOptions.ThreadsPerCore){
                            let instancevCPUs = instance.CpuOptions.CoreCount * instance.CpuOptions.ThreadsPerCore;
                            ec2vCPUs += instancevCPUs;
                        }
                    }
                }
            }

            var percentage = Math.ceil((ec2vCPUs / vCPUsLimit)*100);
            var returnMsg = 'Account contains ' + ec2vCPUs + ' of ' + vCPUsLimit + ' (' + percentage + '%) available vCPUs';

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