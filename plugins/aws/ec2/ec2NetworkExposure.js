var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Internet Exposure',
    category: 'EC2',
    domain: 'Compute',
    severity: 'Info',
    description: 'Check if EC2 instances are exposed to the internet.',
    more_info: 'EC2 instances exposed to the internet are at a higher risk of unauthorized access, data breaches, and cyberattacks. It’s crucial to limit exposure by securing access through proper configuration of security groups, NACLs, and route tables.',
    link: 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Security.html',
    recommended_action: 'Secure EC2 instances by restricting access with properly configured security groups and NACLs.',
    apis: ['EC2:describeInstances', 'EC2:describeNetworkAcls', 'EC2:describeSecurityGroups', 'EC2:describeNetworkInterfaces', 'EC2:describeSubnets',
        'EC2:describeRouteTables', 'ELB:describeLoadBalancers','ELBv2:describeLoadBalancers', 'ELBv2:describeTargetGroups', 'ELBv2:describeTargetHealth', 'ELBv2:describeListeners'],
    realtime_triggers: ['ec2:RunInstances','ec2:TerminateInstances', 'ec2:CreateNetworkAcl', 'ec2:ReplaceNetworkAclEntry', 'ec2:ReplaceNetworkAclAssociation',
        'ec2:DeleteNetworkAcl', 'ec2:CreateSecurityGroup', 'ec2:AuthorizeSecurityGroupIngress','ec2:ModifySecurityGroupRules','ec2:RevokeSecurityGroupIngress',
        'ec2:DeleteSecurityGroup', 'ec2:ModifyInstanceAttribute', 'ec2:ModifySubnetAttribute', 'elasticloadbalancing:CreateLoadBalancer', 'elasticloadbalancing:ModifyTargetGroups', 'elasticloadbalancing:RegisterTarget', 'elasticloadbalancing:DeregisterTargets', 'elasticloadbalancing:DeleteLoadBalancer',
        'elasticloadbalancing:DeleteTargetGroup', 'elasticloadbalancing:RegisterInstancesWithLoadBalancer', 'elasticloadbalancing:DeregisterInstancesWithLoadBalancer','elasticloadbalancing:CreateListener', 'elasticloadbalancing:DeleteListener'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var awsOrGov = helpers.defaultPartition(settings);

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

            for (var instances of describeInstances.data){
                const { OwnerId } = instances;
                for (var instance of instances.Instances) {
                    const { InstanceId } = instance;
                    const arn = `arn:${awsOrGov}:ec2:${region}:${OwnerId}:instance/${InstanceId}`;

                    // List all ELB's attached to the instance
                    let elbs = helpers.getAttachedELBs(cache, source, region, InstanceId, 'Instances', 'InstanceId');

                    let internetExposed = helpers.checkNetworkExposure(cache, source, [{id: instance.SubnetId}], instance.SecurityGroups, elbs, region, results, instance);
                    if (internetExposed && internetExposed.length) {
                        helpers.addResult(results, 2, `EC2 instance is exposed to the internet through ${internetExposed}`, region, arn);
                    } else {
                        helpers.addResult(results, 0, 'EC2 instance is not exposed to the internet', region, arn);
                    }
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
