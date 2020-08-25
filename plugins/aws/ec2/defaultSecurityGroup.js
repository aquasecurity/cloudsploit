var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Default Security Group',
    category: 'EC2',
    description: 'Ensure the default security groups block all traffic by default',
    more_info: 'The default security group is often used for resources launched without a defined security group. For this reason, the default rules should be to block all traffic to prevent an accidental exposure.',
    link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-network-security.html#default-security-group',
    recommended_action: 'Update the rules for the default security group to deny all traffic by default',
    apis: ['EC2:describeSecurityGroups'],
    compliance: {
        pci: 'PCI has strict requirements to segment networks using firewalls. ' +
             'Security groups are a software-layer firewall that should be used ' +
             'to isolate resources. Ensure default security groups to not allow ' +
             'unintended traffic to cross these isolation boundaries.',
        cis2: '4.3 Ensure the default security group of every VPC restricts all traffic'
    },

    run: function(cache, settings, callback) {
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

            for (var s in describeSecurityGroups.data) {
                var sg = describeSecurityGroups.data[s];
                // arn:aws:ec2:region:account-id:security-group/security-group-id
                var resource = 'arn:aws:ec2:' + region + ':' + sg.OwnerId + ':security-group/' + sg.GroupId;

                if (sg.GroupName === 'default') {
                    if (sg.IpPermissions.length ||
                         sg.IpPermissionsEgress.length) {
                        helpers.addResult(results, 2,
                            'Default security group has ' + (sg.IpPermissions.length || '0') + ' inbound and ' + (sg.IpPermissionsEgress.length || '0') + ' outbound rules',
                            region, resource);
                    } else {
                        helpers.addResult(results, 0,
                            'Default security group does not have inbound or outbound rules',
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
