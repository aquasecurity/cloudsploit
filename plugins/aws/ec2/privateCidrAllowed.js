var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EC2 Security Group RFC 1918',
    category: 'EC2',
    description: 'Ensures EC2 security groups are not configured to allow inbound traffic from RFC-1918 CIDRs',
    more_info: 'RFC-1918 IP addresses are considered reserved private addresses and should not be used in security groups.',
    link: 'https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rfc1918.html',
    recommended_action: 'Modify the security group to ensure the private reserved addresses are not allowed for inbound traffic',
    apis: ['EC2:describeSecurityGroups'],
    settings: {
        privateCidrs: {
            name: 'EC2 RFC 1918 CIDR Addresses',
            description: 'A comma-delimited list of CIDRs that indicates reserved private addresses',
            regex: '[a-zA-Z0-9,]',
            default: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var privateCidrs = settings.privateCidrs || this.settings.privateCidrs.default;

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
                var resource = group.GroupId;
                var privateCidrFound = [];

                if (!group.IpPermissions || !group.IpPermissions.length) continue;

                for (var p in group.IpPermissions) {
                    var permission = group.IpPermissions[p];

                    for (var r in permission.IpRanges) {
                        var cidrIp = permission.IpRanges[r].CidrIp;
                        if (cidrIp && privateCidrs.includes(cidrIp)) {
                            if(!privateCidrFound.includes(cidrIp)) {
                                privateCidrFound.push(cidrIp);
                            }
                        }
                    }

                    if(privateCidrFound.length) {
                        helpers.addResult(results, 2,
                            'Security group ' + group.GroupName + ' has inbound access allowed for reserved private addresses: ' + privateCidrFound.join(' , '), 
                            region, resource);
                    }
                    else {
                        helpers.addResult(results, 0, 'Security group ' + group.GroupName + ' has no reserved private addresses allowed', region);
                    }
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    
    }
};