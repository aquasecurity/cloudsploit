var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Open All Ports Protocols Egress',
    category: 'EC2',
    domain: 'Compute',
    description: 'Determine if security group has all outbound ports or protocols open to the public',
    more_info: 'Security groups should be created on a per-service basis and avoid allowing all ports or protocols in order to implement the Principle of Least Privilege (POLP) and reduce the attack surface.',
    link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
    recommended_action: 'Modify the security group tp restrict access to only those IP addresses and/or IP ranges that require it.',
    apis: ['EC2:describeSecurityGroups', 'EC2:describeNetworkInterfaces', 'Lambda:listFunctions'],
    settings: {
        ec2_skip_unused_groups: {
            name: 'EC2 Skip Unused Groups',
            description: 'When set to true, skip checking ports for unused security groups and produce a WARN result',
            regex: '^(true|false)$',
            default: 'false',
        }
    },
    run: function(cache, settings, callback) {
        var config = {
            ec2_skip_unused_groups: settings.ec2_skip_unused_groups || this.settings.ec2_skip_unused_groups.default,
        };

        config.ec2_skip_unused_groups = (config.ec2_skip_unused_groups == 'true');
        
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ec2, function(region, rcb){
            var describeSecurityGroups = helpers.addSource(cache, source,
                ['ec2', 'describeSecurityGroups', region]);

            if (!describeSecurityGroups) return rcb();

            if (describeSecurityGroups.err || !describeSecurityGroups.data) {
                helpers.addResult(results, 3,
                    'Unable to query for security groups: ' + helpers.addError(describeSecurityGroups), region);
                return rcb();
            }

            if (!describeSecurityGroups.data.length) {
                helpers.addResult(results, 0, 'No security groups present', region);
                return rcb();
            }

            if (config.ec2_skip_unused_groups) {
                var usedGroups = helpers.getUsedSecurityGroups(cache, results, region, rcb);
            }

            let strings = [];
            for (let group of describeSecurityGroups.data){
                strings = [];
                let resource = 'arn:aws:ec2:' + region + ':' + group.OwnerId + ':security-group/' + group.GroupId;
                for (let permission of group.IpPermissionsEgress){
                    for (let range  of permission.IpRanges) {
                        if (range.CidrIp === '0.0.0.0/0') {
                            if (!permission.FromPort && !permission.ToPort) {
                                var string = 'all ports open to 0.0.0.0/0';
                                if (strings.indexOf(string) === -1) strings.push(string);
                            }

                            if (permission.IpProtocol === '-1') {
                                var stringO = 'all protocols open to 0.0.0.0/0';
                                if (strings.indexOf(stringO) === -1) strings.push(stringO);
                            }
                        }
                    }
                    for (var rangeV6 of permission.Ipv6Ranges) {

                        if (rangeV6.CidrIpv6 === '::/0') {
                            if (!permission.FromPort && !permission.ToPort ) {
                                var stringV6 = 'all ports open to ::/0';
                                if (strings.indexOf(stringV6) === -1) strings.push(stringV6);
                            }

                            if (permission.IpProtocol === '-1') {
                                var stringP = 'all protocols open to ::/0';
                                if (strings.indexOf(stringP) === -1) strings.push(stringP);
                            }
                        }
                    }
                }
                if (strings.length) {
                    if (config.ec2_skip_unused_groups && group.GroupId && !usedGroups.includes(group.GroupId)) {
                        helpers.addResult(results, 1, `Security Group: ${group.GroupId} is not in use`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'Security group: ' + group.GroupId +
                            ' (' + group.GroupName +
                            ') has ' + strings.join(' and '), region,
                            resource);
                    }   
                } else {
                    helpers.addResult(results, 0,
                        `Security group: ${group.GroupId} (${group.GroupName}) does not have all ports or protocols open to the public`,
                        region, resource);
                }
            }
        
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
