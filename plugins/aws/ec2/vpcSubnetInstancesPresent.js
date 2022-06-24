var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'VPC Subnet Instances Present',
    category: 'EC2',
    domain: 'Compute',
    description: 'Ensures that there are instances attached to every subnet.',
    more_info: 'All subnets should have instances associated and unused subnets should be removed to avoid reaching the limit.',
    recommended_action: 'Update VPC subnets and attach instances to it or remove the unused VPC subnets',
    link: 'https://docs.aws.amazon.com/vpc/latest/userguide/vpc-endpoints-access.html',
    apis: ['EC2:describeInstances', 'EC2:describeSubnets'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ec2, function(region, rcb){
            var describeSubnets = helpers.addSource(cache, source,
                ['ec2', 'describeSubnets', region]);

            if (!describeSubnets) return rcb();

            if (describeSubnets.err || !describeSubnets.data) {
                helpers.addResult(results, 3,
                    `Unable to query for VPC subnets: ${helpers.addError(describeSubnets)}`, region);
                return rcb();
            }

            if (!describeSubnets.data.length) {
                helpers.addResult(results, 0, 'No VPC subnets found', region);
                return rcb();
            }

            var describeInstances = helpers.addSource(cache, source,
                ['ec2', 'describeInstances', region]);

            if (!describeInstances || describeInstances.err || !describeInstances.data) {
                helpers.addResult(results, 3,
                    `Unable to query for EC2 instances: ${helpers.addError(describeInstances)}`, region);
                return rcb();
            }

            var instanceSubnets = {};
            if (describeInstances.data.length) {
                describeInstances.data.forEach(instance => {
                    if (instance.Instances && instance.Instances.length) {
                        instance.Instances.forEach(entry => {
                            if (entry.SubnetId && instanceSubnets[entry.SubnetId]) instanceSubnets[entry.SubnetId] += 1;
                            else if (entry.SubnetId) instanceSubnets[entry.SubnetId] = 1;
                        });
                    }
                });
            }

            describeSubnets.data.forEach(subnet => {
                if (subnet.SubnetId && instanceSubnets[subnet.SubnetId]) {
                    helpers.addResult(results, 0,
                        `Subnet has ${instanceSubnets[subnet.SubnetId]} instances attached`,
                        region, subnet.SubnetArn);
                } else {
                    helpers.addResult(results, 2,
                        'Subnet does not have any instance attached',
                        region, subnet.SubnetArn);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};