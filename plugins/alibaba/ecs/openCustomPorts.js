var async = require('async');
var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Open Custom Ports',
    category: 'ECS',
    domain: 'Compute',
    description: 'Ensure that defined custom ports are not open to public.',
    more_info: 'Security groups should restrict access to ports from known networks.',
    link: 'https://www.alibabacloud.com/help/doc-detail/25471.htm',
    recommended_action: 'Modify the security group to ensure the defined custom ports are not exposed publicly',
    apis: ['ECS:DescribeSecurityGroups', 'ECS:DescribeSecurityGroupAttribute', 'STS:GetCallerIdentity'],
    settings: {
        restricted_open_ports: {
            name: 'Restricted Open Ports',
            description: 'Comma separated list of ports/port-ranges that should be restricted and not publicly open. Example: tcp:80,tcp:443,tcp:80-443',
            regex: '[a-zA-Z0-9,:]',
            default: ''
        },
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var restricted_open_ports = settings.restricted_open_ports || this.settings.restricted_open_ports.default;

        if (!restricted_open_ports.length) return callback();

        restricted_open_ports = restricted_open_ports.split(',');

        var ports = {};
        restricted_open_ports.forEach(port => {
            var [protocol, portNo] = port.split(':');
            if (ports[protocol]) {
                ports[protocol].push(portNo);
            } else {
                ports[protocol] = [portNo];
            }
        });

        async.each(regions.ecs, function(region, rcb){
            var describeSecurityGroups = helpers.addSource(cache, source,
                ['ecs', 'DescribeSecurityGroups', region]);

            if (!describeSecurityGroups) return rcb();

            if (describeSecurityGroups.err || !describeSecurityGroups.data) {
                helpers.addResult(results, 3,
                    `Unable to describe security groups: ${helpers.addError(describeSecurityGroups)}`, region);
                return rcb();
            }

            if (!describeSecurityGroups.data.length) {
                helpers.addResult(results, 0, 'No security groups found', region);
                return rcb();
            }

            helpers.findOpenPorts(cache, describeSecurityGroups.data, ports, 'custom', region, results);

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
