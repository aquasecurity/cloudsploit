var async = require('async');
var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Open All Ports Protocols',
    category: 'ECS',
    description: 'Ensure that ECS security groups do not have all ports or protocols open to the public',
    more_info: 'Security groups should be created on a per-service basis and avoid allowing all ports or protocols.',
    link: 'https://partners-intl.aliyun.com/help/doc-detail/51170.htm',
    recommended_action: 'Modify the security group to specify a specific port and protocol to allow.',
    apis: ['ECS:DescribeSecurityGroups', 'ECS:DescribeSecurityGroupAttribute', 'STS:GetCallerIdentity'],
    compliance: {
        hipaa: 'HIPAA requires strict access controls to networks and services ' +
                'processing sensitive data. Security groups are the built-in ' +
                'method for restricting access to Alibaba services and should be ' +
                'configured to allow least-privilege access.',
        pci: 'PCI has explicit requirements around firewalled access to systems. ' +
             'Security groups should be properly secured to prevent access to ' +
             'backend services.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var defaultRegion = helpers.defaultRegion(settings);

        var accountId = helpers.addSource(cache, {}, ['sts', 'GetCallerIdentity', defaultRegion, 'data']);

        async.each(regions.ecs, function(region, rcb){
            var describeSecurityGroups = helpers.addSource(cache, source,
                ['ecs', 'DescribeSecurityGroups', region]);

            if (!describeSecurityGroups) return rcb();

            if (describeSecurityGroups.err || !describeSecurityGroups.data) {
                helpers.addResult(results, 3,
                    'Unable to describe security groups: ' + helpers.addError(describeSecurityGroups), region);
                return rcb();
            }

            if (!describeSecurityGroups.data.length) {
                helpers.addResult(results, 0, 'No security groups found', region);
                return rcb();
            }

            var found = false;
            async.each(describeSecurityGroups.data, (group, scb)=> {
                var strings = [];
                var resource = helpers.createArn('ecs', accountId, 'securitygroup', group.SecurityGroupId, region);

                var describeSecurityGroupAttribute = helpers.addSource(cache, {},
                    ['ecs', 'DescribeSecurityGroupAttribute', region, group.SecurityGroupId]);
        
                if (!describeSecurityGroupAttribute || describeSecurityGroupAttribute.err || !describeSecurityGroupAttribute.data) {
                    helpers.addResult(results, 3,
                        `Unable to query security group attributes: ${describeSecurityGroupAttribute}`, region, resource);
                    return scb();
                }

                if (describeSecurityGroupAttribute.data.Permissions &&
                    describeSecurityGroupAttribute.data.Permissions.Permission &&
                    describeSecurityGroupAttribute.data.Permissions.Permission.length){
                    for (var permission of describeSecurityGroupAttribute.data.Permissions.Permission) {
                        if (permission.Direction && permission.Direction !== 'ingress') continue;
                        if (permission.SourceCidrIp === '0.0.0.0/0') {
                            if (permission.PortRange == '-1/-1') {
                                var string = 'all ports open to 0.0.0.0/0';
                                if (strings.indexOf(string) === -1) strings.push(string);
                                found = true;
                            }
    
                            if (permission.IpProtocol && permission.IpProtocol.toUpperCase() === 'ALL') {
                                var stringO = 'all protocols open to 0.0.0.0/0';
                                if (strings.indexOf(stringO) === -1) strings.push(stringO);
                                found = true;
                            } 
                        }
                    }
                }

                if (strings.length) {
                    helpers.addResult(results, 2,
                        `Security group: ${group.SecurityGroupId} has ${strings.join(' and ')}`,
                        region, resource);
                }

                scb();
            }, function(){
                if (!found) {
                    helpers.addResult(results, 0, 'No public open ports found', region);
                }

                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};
