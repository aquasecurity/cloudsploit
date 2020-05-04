var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Open SSH',
    category: 'EC2',
    description: 'Determine if TCP port 22 for SSH is open to the public',
    more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as SSH should be restricted to known IP addresses.',
    link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
    recommended_action: 'Restrict TCP port 22 to known IP addresses',
    apis: ['EC2:describeSecurityGroups'],
    remediation_description: 'The impacted security group rule will have its public IP address replaced with the localhost IP.',
    apis_remediate: ['EC2:describeSecurityGroups'],
    apis_compare: ['EC2:describeSecurityGroups'],
    actions: {
        remediate: ['EC2:authorizeSecurityGroupIngress','EC2:revokeSecurityGroupIngress'],
        rollback: ['EC2:authorizeSecurityGroupIngress']
    },
    permissions: {
        remediate: ['ec2:AuthorizeSecurityGroupIngress','ec2:RevokeSecurityGroupIngress'],
        rollback:['ec2:AuthorizeSecurityGroupIngress']
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var ports = {
            'tcp': [22]
        };

        var service = 'SSH';

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

            helpers.findOpenPorts(describeSecurityGroups.data, ports, service, region, results);

            rcb();
        }, function(){
            callback(null, results, source);
        });
    },
    remediate: function(config, cache, settings, resources, callback) {
        var putCall = this.actions.remediate;
        var source = {};
        var pluginName = 'openSSH';

        var sgId = resources.split('/')[1];
        config.region = resources.split(':')[3];

        var describeSecurityGroups = helpers.addSource(cache, source,
            ['ec2', 'describeSecurityGroups', config.region]);

        var securityGroup = describeSecurityGroups.data.find(group => {
            return group.GroupId === sgId;
        });

        var failingPermissions = securityGroup.IpPermissions.filter(permission => {
            return (permission.FromPort === 22 && permission.IpProtocol === 'tcp');
        });
        var remediation_file = settings.remediation_file;
        remediation_file['remediate']['actions'][pluginName][resources]['steps'] = [];
        failingPermissions.forEach(failingPermission => {
            var openIpRange = false;
            var openIpv6Range = false;
            var finalIpRanges = [];
            var finalIpv6Ranges = [];

            if (failingPermission.IpRanges && failingPermission.IpRanges.length) {
                failingPermission.IpRanges.forEach(ipRange => {
                    if (ipRange.CidrIp && ipRange.CidrIp === '0.0.0.0/0') {
                        openIpRange = true
                    } else {
                        finalIpRanges.push(ipRange)
                    }
                })
            }

            if (failingPermission.Ipv6Ranges && failingPermission.Ipv6Ranges.length) {
                failingPermission.Ipv6Ranges.forEach(ipv6Range => {
                    if (ipv6Range.CidrIpv6 && ipv6Range.CidrIpv6 === '::/0') {
                        openIpv6Range = true
                    } else {
                        finalIpv6Ranges.push(ipv6Range)
                    }
                })
            }
            var params = {
                DryRun: false,
                GroupId: securityGroup.GroupId,
                IpPermissions: [
                    {
                        IpRanges: failingPermission.IpRanges,
                        Ipv6Ranges: failingPermission.Ipv6Ranges,
                        PrefixListIds: failingPermission.PrefixListIds.length ? failingPermission.PrefixListIds : null,
                        UserIdGroupPairs: failingPermission.UserIdGroupPairs.length ? failingPermission.UserIdGroupPairs : null,
                        ToPort: failingPermission.ToPort,
                        FromPort: failingPermission.FromPort,
                        IpProtocol: failingPermission.IpProtocol,
                    }
                ],
            };
            remediation_file['pre_remediate']['actions'][pluginName][resources] = JSON.parse(JSON.stringify(params));

            params.IpPermissions[0].Ipv6Ranges.length = 0;
            params.IpPermissions[0].IpRanges.length = 0;
            params.IpPermissions[0].UserIdGroupPairs = null;

            if (openIpRange && openIpv6Range) {
                var oldIpv6Range = {
                    CidrIpv6 : "::/0"
                };
                var newIpv6Range = {
                    CidrIpv6 : "::1/128"
                };
                var oldIpRange = {
                    CidrIp : "0.0.0.0/0"
                };
                var newIpRange = {
                    CidrIp : "127.0.0.1/32"
                };

                params.IpPermissions[0].Ipv6Ranges.push(newIpv6Range);
                params.IpPermissions[0].IpRanges.push(newIpRange);
                finalIpRanges.push(newIpRange);
                finalIpv6Ranges.push(newIpv6Range);

                helpers.remediatePlugin(config, putCall[0], params, function (err, results) {
                    if (err) {
                        remediation_file['post_remediate']['actions'][pluginName]['error'] = err;
                        return callback(err, null);
                    }

                    remediation_file['remediate']['actions'][pluginName][resources]['steps'].push({
                        'inboundRule': '::1/128',
                        'action': 'ADDED'
                    });

                    remediation_file['remediate']['actions'][pluginName][resources]['steps'].push({
                        'inboundRule': '127.0.0.1/32',
                        'action': 'ADDED'
                    });


                    params.IpPermissions[0].Ipv6Ranges.length = 0;
                    params.IpPermissions[0].IpRanges.length = 0;
                    params.IpPermissions[0].IpRanges.push(oldIpRange);
                    params.IpPermissions[0].Ipv6Ranges.push(oldIpv6Range);

                    helpers.remediatePlugin(config, putCall[1], params, function (err, results) {
                        if (err) {
                            remediation_file['post_remediate']['actions'][pluginName]['error'] = err;
                            return callback(err, null);
                        }

                        remediation_file['remediate']['actions'][pluginName][resources]['steps'].push({
                            'inboundRule': '::/0',
                            'action': 'DELETED'
                        });
                        remediation_file['remediate']['actions'][pluginName][resources]['steps'].push({
                            'inboundRule': '0.0.0.0/0',
                            'action': 'DELETED'
                        });

                        params.IpPermissions[0].Ipv6Ranges = finalIpRanges;
                        params.IpPermissions[0].IpRanges = finalIpv6Ranges;
                        params.IpPermissions[0].UserIdGroupPairs = failingPermission.UserIdGroupPairs.length ? failingPermission.UserIdGroupPairs : null;

                        remediation_file['post_remediate']['actions'][pluginName][resources] = JSON.parse(JSON.stringify(params));
                        settings.remediation_file = remediation_file;
                        return callback(null, params);
                    });
                });
            } else if (openIpv6Range) {
                var oldIpv6Range = {
                    CidrIpv6 : "::/0"
                };
                var newIpv6Range = {
                    CidrIpv6 : "::1/128"
                };

                params.IpPermissions[0].IpRanges = null;
                params.IpPermissions[0].Ipv6Ranges.push(newIpv6Range);
                finalIpv6Ranges.push(newIpv6Range);
                helpers.remediatePlugin(config, putCall[0], params, function (err, results) {
                    if (err) {
                        remediation_file['post_remediate']['actions'][pluginName]['error'] = err;

                        return callback(err, null);
                    }

                    remediation_file['remediate']['actions'][pluginName][resources]['steps'].push({
                        'inboundRule': '::1/128',
                        'action': 'ADDED'
                    });

                    params.IpPermissions[0].Ipv6Ranges.length = 0;
                    params.IpPermissions[0].Ipv6Ranges.push(oldIpv6Range);

                    helpers.remediatePlugin(config, putCall[1], params, function (err, results) {
                        if (err) {
                            remediation_file['post_remediate']['actions'][pluginName]['error'] = err;
                            return callback(err, null);
                        }

                        remediation_file['remediate']['actions'][pluginName][resources]['steps'].push({
                            'inboundRule': '::/0',
                            'action': 'DELETED'
                        });

                        params.IpPermissions[0].Ipv6Ranges = finalIpv6Ranges;
                        params.IpPermissions[0].IpRanges = finalIpRanges.length ? finalIpRanges : null;
                        params.IpPermissions[0].UserIdGroupPairs = failingPermission.UserIdGroupPairs.length ? failingPermission.UserIdGroupPairs : null;

                        remediation_file['post_remediate']['actions'][pluginName][resources] = JSON.parse(JSON.stringify(params));

                        settings.remediation_file = remediation_file;
                        return callback(null, params);
                    });
                });
            } else if (openIpRange) {
                var oldIpRange = {
                    CidrIp : "0.0.0.0/0"
                };
                var newIpRange = {
                    CidrIp : "127.0.0.1/32"
                };

                params.IpPermissions[0].Ipv6Ranges = null;
                params.IpPermissions[0].IpRanges.push(newIpRange);
                finalIpRanges.push(newIpRange);

                helpers.remediatePlugin(config, putCall[0], params, function (err, results) {
                    if (err) {
                        remediation_file['post_remediate']['actions'][pluginName]['error'] = err;
                        return callback(err, null);
                    }

                    remediation_file['remediate']['actions'][pluginName][resources]['steps'].push({
                        'inboundRule': '127.0.0.1/32',
                        'action': 'ADDED'
                    });

                    params.IpPermissions[0].IpRanges.length = 0;
                    params.IpPermissions[0].IpRanges.push(oldIpRange);

                    helpers.remediatePlugin(config, putCall[1], params, function (err, results) {
                        if (err) {
                            remediation_file['post_remediate']['actions'][pluginName]['error'] = err;
                            return callback(err, null);
                        }

                        remediation_file['remediate']['actions'][pluginName][resources]['steps'].push({
                            'inboundRule': '0.0.0.0',
                            'action': 'DELETED'
                        });
                        params.IpPermissions[0].Ipv6Ranges = finalIpv6Ranges.length ? finalIpv6Ranges : null;
                        params.IpPermissions[0].IpRanges = finalIpRanges;
                        params.IpPermissions[0].UserIdGroupPairs = failingPermission.UserIdGroupPairs.length ? failingPermission.UserIdGroupPairs : null;

                        remediation_file['post_remediate']['actions'][pluginName][resources] = JSON.parse(JSON.stringify(params));

                        settings.remediation_file = remediation_file;
                        return callback(null, params);
                    });
                });
            } else {
                return callback("No IP Addresses found");
            }
        });
    }
};
