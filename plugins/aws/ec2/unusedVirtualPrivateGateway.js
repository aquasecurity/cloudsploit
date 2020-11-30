var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Unused Virtual Private Gateway',
    category: 'EC2',
    description: 'Ensures that unused Virtual Private Gateways (VGWs) are removed.',
    more_info: 'Unused VGWs should be remove to follow best practices and to avoid reaching the service limit.',
    link: 'https://docs.aws.amazon.com/vpn/latest/s2svpn/delete-vpn.html',
    recommended_action: 'Remove the unused Virtual Private Gateways (VGWs)',
    apis: ['EC2:describeVpnGateways', 'STS:getCallerIdentity'],

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
                var vpnAttached = false;
                if (vpn.VpcAttachments && vpn.VpcAttachments.length) {
                    for(var v in vpn.VpcAttachments) {
                        var attachment = vpn.VpcAttachments[v];
                        if(attachment.State && attachment.State === 'attached') {
                            vpnAttached = true;
                            break;
                        }
                    }
                }

                if(vpnAttached) {
                    helpers.addResult(results, 0,
                        `Virtual Private Gateway "${vpn.VpnGatewayId}" is in use`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `Virtual Private Gateway "${vpn.VpnGatewayId}" is not in use`,
                        region, resource);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};