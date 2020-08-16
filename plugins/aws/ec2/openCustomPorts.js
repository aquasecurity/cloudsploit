var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Open Custom Ports',
    category: 'EC2',
    description: 'Ensures that the defined ports are not exposed publicly.',
    more_info: 'Security groups should be used to restrict access to ports from known networks.',
    link: 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html',
    recommended_action: 'Modify the security group to ensure the ports are not exposed publicly.',
    apis: ['EC2:describeSecurityGroups'],
    settings: {
        open_port_allowed_list: {
            name: 'EC2 Allowed Open Ports',
            description: 'A comma-delimited list of ports that indicates open ports allowed for any connection',
            regex: '[a-zA-Z0-9,]',
            default: [22, 443]
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var allowed_open_ports = this.settings.open_port_allowed_list.default;

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

            var found = false;
            var groups = describeSecurityGroups.data;

            for (var g in groups) {
                var strings = [];
                var resource = 'arn:aws:ec2:' + region + ':' +
                               groups[g].OwnerId + ':security-group/' +
                               groups[g].GroupId;

                for (var p in groups[g].IpPermissions) {
                    var permission = groups[g].IpPermissions[p];
                    
                    for (var k in permission.IpRanges) {
                        var range = permission.IpRanges[k];

                        if (range.CidrIp === '0.0.0.0/0') {
                            var portRange = permission.ToPort - permission.FromPort;

                            for (let p=0; p <= portRange; p++) {
                                var port = permission.FromPort + p;

                                if (!allowed_open_ports.includes(port)) {
                                    var string = permission.IpProtocol.toUpperCase() +
                                    ' port ' + port + ' open to 0.0.0.0/0';
                                    if (strings.indexOf(string) === -1) strings.push(string);
                                    found = true;
                                }
                            }
                        }
                    }
                }

                if (strings.length) {
                    helpers.addResult(results, 2,
                        'Security group: ' + groups[g].GroupId +
                        ' (' + groups[g].GroupName +
                        ') has ' + ': ' + strings.join(' and '), region,
                        resource);
                }
            }

            if (!found) {
                helpers.addResult(results, 0, 'No public open ports found', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
