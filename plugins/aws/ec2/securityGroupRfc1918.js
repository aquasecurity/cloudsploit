var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Open RFC 1918',
    category: 'EC2',
    description: 'Ensures EC2 security groups are configured to deny inbound traffic from RFC-1918 CIDRs',
    more_info: 'RFC-1918 IP addresses are considered reserved private addresses and should not be used in security groups.',
    link: 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Subnets.html',
    recommended_action: 'Modify the security group to deny private reserved addresses for inbound traffic',
    apis: ['EC2:describeSecurityGroups'],
    settings: {
        privateCidrs: {
            name: 'EC2 RFC 1918 CIDR Addresses',
            description: 'A comma-delimited list of CIDRs that indicates reserved private addresses',
            regex: '/^(?=.*[^.]$)((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).?){4}$/',
            default: '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        var privateCidrs = settings.privateCidrs || this.settings.privateCidrs.default;
        privateCidrs = privateCidrs.split(',');

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
                helpers.addResult(results, 0, 'No security groups found', region);
                return rcb();
            }

            for (var g in describeSecurityGroups.data) {
                var group = describeSecurityGroups.data[g];
                var resource = 'arn:' + awsOrGov + ':ec2:' + region + ':' + group.OwnerId + ':security-group/' + group.GroupId;
                var privateCidrsFound = [];

                if (!group.IpPermissions || !group.IpPermissions.length) {
                    helpers.addResult(results, 0,
                        'Security group :' + group.GroupName + ': does not have any IP permissions', region, resource);
                    continue;
                }

                for (var p in group.IpPermissions) {
                    var permission = group.IpPermissions[p];

                    for (var r in permission.IpRanges) {
                        var cidrIp = permission.IpRanges[r].CidrIp;
                        if (cidrIp && privateCidrs.includes(cidrIp)) {
                            if(!privateCidrsFound.includes(cidrIp)) {
                                privateCidrsFound.push(cidrIp);
                            }
                        }
                    }

                    if(!privateCidrsFound.length) {
                        helpers.addResult(results, 0,
                            'Security group "' + group.GroupName + '" is not configured to allow traffic from any reserved private addresses',
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'Security group "' + group.GroupName + '" is configured to allow inbound access for these reserved private addresses: ' + privateCidrsFound.join(', '), 
                            region, resource);
                    }
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    
    }
};
