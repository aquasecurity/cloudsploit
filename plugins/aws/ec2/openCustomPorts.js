var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Open Custom Ports',
    category: 'EC2',
    description: 'Ensure that defined custom ports are not open to public.',
    more_info: 'Security groups should restrict access to ports from known networks.',
    link: 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html',
    recommended_action: 'Modify the security group to ensure the defined custom ports are not exposed publicly',
    apis: ['EC2:describeSecurityGroups'],
    settings: {
        restricted_open_ports: {
            name: 'Restricted Open Ports',
            description: 'Comma separated list of ports that should be restricted and not publicly open. Example: tcp:80,tcp:443',
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
                ports[protocol].push(Number(portNo));
            } else {
                ports[protocol] = [Number(portNo)];
            }
        });

        async.each(regions.ec2, function(region, rcb){
            var describeSecurityGroups = helpers.addSource(cache, source,
                ['ec2', 'describeSecurityGroups', region]);

            if (!describeSecurityGroups) return rcb();

            if (describeSecurityGroups.err || !describeSecurityGroups.data) {
                helpers.addResult(results, 3,
                    `Unable to query for security groups: ${helpers.addError(describeSecurityGroups)}`, region);
                return rcb();
            }

            if (!describeSecurityGroups.data.length) {
                helpers.addResult(results, 0, 'No security groups present', region);
                return rcb();
            }

            helpers.findOpenPorts(describeSecurityGroups.data, ports, 'custom', region, results);

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
