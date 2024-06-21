var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Open HTTP',
    category: 'EC2',
    domain: 'Compute',
    severity: 'High',
    description: 'Determine if TCP port 80 for HTTP is open to the public',
    more_info: 'While some ports are required to be open to the public to function properly, more sensitive services such as HTTP should be restricted to known IP addresses.',
    link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
    recommended_action: 'Restrict TCP port 80 to known IP addresses',
    apis: ['EC2:describeSecurityGroups','EC2:describeNetworkInterfaces'],
    realtime_triggers: ['ec2:CreateSecurityGroup','ec2:AuthorizeSecurityGroupIngress','ec2:ModifySecurityGroupRules', 'ec2:RevokeSecurityGroupIngress', 'ec2:DeleteSecurityGroup'],
    settings: {
        ec2_skip_unused_groups: {
            name: 'EC2 Skip Unused Groups',
            description: 'When set to true, skip checking ports for unused security groups and produce a WARN result',
            regex: '^(true|false)$',
            default: 'false',
        },
        check_network_interface: {
            name: 'Check Associated ENI',
            description: 'When set to true, checks elastic network interfaces associated to the security group and returns FAIL if both the security group and ENI are publicly exposed',
            regex: '^(true|false)$',
            default: 'false',
        }
    },

    run: function(cache, settings, callback) {

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            ec2_skip_unused_groups: settings.ec2_skip_unused_groups || this.settings.ec2_skip_unused_groups.default,
            check_network_interface: settings.check_network_interface || this.settings.check_network_interface.default,
        };

        config.ec2_skip_unused_groups = (config.ec2_skip_unused_groups == 'true');
        config.check_network_interface = (config.check_network_interface == 'true');

        var ports = {
            'tcp': [80]
        };

        var service = 'HTTP';

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
            helpers.findOpenPorts(describeSecurityGroups.data, ports, service, region, results, cache, config, rcb, settings);


            rcb();
        }, function(){
            callback(null, results, source);
        });
    },
};
