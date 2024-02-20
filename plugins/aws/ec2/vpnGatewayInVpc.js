var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Virtual Private Gateway In VPC',
    category: 'EC2',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensure Virtual Private Gateways are associated with at least one VPC.',
    more_info: 'Virtual Private Gateways allow communication between cloud infrastructure and the remote customer network. They help in establishing VPN connection between VPC and the customer gateway. ' +
        'Make sure virtual private gateways are always associated with a VPC to meet security and regulatory compliance requirements within your organization.',
    link: 'https://docs.aws.amazon.com/vpn/latest/s2svpn/SetUpVPNConnections.html',
    recommended_action: 'Check if virtual private gateways have vpc associated',
    apis: ['EC2:describeVpnGateways', 'STS:getCallerIdentity'],
    realtime_triggers: ['ec2:CreateVpnGateway', 'ec2:AttachVpnGateway', 'ec2:DeattachVpnGateway', 'ec2:DeleteVpnGateway'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ec2, function(region, rcb){
            var describeVpnGateways = helpers.addSource(cache, source,
                ['ec2', 'describeVpnGateways', region]);

            if (!describeVpnGateways) return rcb();

            if (describeVpnGateways.err || !describeVpnGateways.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Virtual Private Gateways: ${helpers.addError(describeVpnGateways)}`,
                    region);
                return rcb();
            }

            if (!describeVpnGateways.data.length) {
                helpers.addResult(results, 0,
                    'No Virtual Private Gateways found', region);
                return rcb();
            }

            describeVpnGateways.data.forEach(function(vpn){
                var resource = `arn:${awsOrGov}:vpc:${region}:${accountId}:vpn-gateway/${vpn.VpnGatewayId}`;
                if (vpn.VpcAttachments && vpn.VpcAttachments.length) {
                    let attached = vpn.VpcAttachments.find(attachment => attachment.VpcId && attachment.State && attachment.State.toUpperCase() == 'ATTACHED');
                    
                    if (attached) {
                        helpers.addResult(results, 0,
                            'Virtual Private Gateway is associated with VPC',
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'Virtual Private Gateway is not associated with VPC',
                            region, resource);
                    }
                } else {
                    helpers.addResult(results, 2,
                        'Virtual Private Gateway is not associated with VPC',
                        region, resource);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};