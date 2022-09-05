var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Virtual Private Gateway Associated VPC',
    category: 'EC2',
    domain: 'Compute',
    description: 'Ensure Virtual Private Gateways are associated with atleast one VPC.',
    more_info: 'Virtual Private Gateways allow communication between cloud infrastructure and the remote customer network. They help in establishing VPN connection between VPC and the customer gateway. By default, AWS VPC has a limit of 5 virtual private gateways per region, so it is a best practice to make sure virtual private gateways are always associated with a VPC and remove any unused virtual private gateways.',
    link: 'https://docs.aws.amazon.com/vpn/latest/s2svpn/delete-vpn.html',
    recommended_action: 'Check if virtual private gateways have vpc associated',
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
                // var vpnAttached = false;
                if (vpn.VpcAttachments && vpn.VpcAttachments.length) {
                    for (var v in vpn.VpcAttachments) {
                        var attachment = vpn.VpcAttachments[v];
                        if (attachment.VpcId) {
                            helpers.addResult(results, 0,
                                `Virtual Private Gateway is associated with VPC`,
                                region, resource);
                        } else {
                            helpers.addResult(results, 2,
                                `Virtual Private Gateway is not associated with VPC`,
                                region, resource);
                        }
                    }
                } else {
                    helpers.addResult(results, 2,
                        `Virtual Private Gateway is not associated with VPC`,
                        region, resource);
                }

              
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};