var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Public IP Address EC2 Instances',
    category: 'EC2',
    description: 'Ensures that EC2 instances do not have public IP address attached.',
    more_info: 'EC2 instances should not have a public IP address attached in order to block public access to the instances.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html',
    recommended_action: 'Remove the public IP address from the EC2 instances to block public access to the instance',
    apis: ['EC2:describeInstances', 'STS:getCallerIdentity', 'EC2:describeSecurityGroups'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ec2, function(region, rcb){
            var describeInstances = helpers.addSource(cache, source,
                ['ec2', 'describeInstances', region]);

            if (!describeInstances) return rcb();

            if (describeInstances.err || !describeInstances.data) {
                helpers.addResult(results, 3,
                    `Unable to query for EC2 instances: ${helpers.addError(describeInstances)}`,
                    region);
                return rcb();
            }

            if (!describeInstances.data.length) {
                helpers.addResult(results, 0, 'No EC2 instances found', region);
                return rcb();
            }

            var describeSecurityGroups = helpers.addSource(cache, source,
                ['ec2', 'describeSecurityGroups', region]);

            if (!describeSecurityGroups || describeSecurityGroups.err || !describeSecurityGroups.data) {
                helpers.addResult(results, 3, `Unable to query security groups: ${helpers.addError(describeSecurityGroups)}`, region);
                return rcb();
            }

            var openSgs = [];

            for (var group of describeSecurityGroups.data) {
                for (var permissions of group.IpPermissions) {
                    for (var range of permissions.IpRanges) {
                        if (range.CidrIp === '0.0.0.0/0') openSgs.push(group.GroupId);
                    }
                    for (var v6range of permissions.Ipv6Ranges) {
                        if (v6range.CidrIpv6 === '::/0') openSgs.push(group.GroupId);
                    }
                }
            }

            describeInstances.data.forEach(function(instance){
                if (!instance.Instances || !instance.Instances.length) {
                    helpers.addResult(results, 0, 
                        'EC2 instance description is not found', region);
                    return;
                }

                instance.Instances.forEach(function(element){
                    var resource = `arn:${awsOrGov}:ec2:${region}:${accountId}:/instance/${element.InstanceId}`;
                    var openSg = false;
                    for (var sg of element.SecurityGroups) {
                        if (openSgs.includes(sg.GroupId)) openSg = true;
                    }

                    if (element.PublicIpAddress && element.PublicIpAddress.length && openSg) {
                        helpers.addResult(results, 2,
                            `EC2 instance "${element.InstanceId}" has a public IP address attached`,
                            region, resource);
                    } else if (element.PublicIpAddress && element.PublicIpAddress.length && !openSg) {
                        helpers.addResult(results, 0,
                            `EC2 instance "${element.InstanceId}" has a public IP address attached but attached security group is not open to public`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 0,
                            `EC2 instance "${element.InstanceId}" does not have a public IP address attached`,
                            region, resource);
                    }
                });
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
