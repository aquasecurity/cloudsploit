var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'VPN Tunnel State',
    category: 'EC2',
    domain: 'Compute',
    description: 'Ensures that each AWS Virtual Private Network (VPN) connection has all tunnels up.',
    more_info: 'AWS Virtual Private Network (VPN) should have tunnels up to ensure network traffic flow over Virtual Private Network.',
    link: 'https://docs.aws.amazon.com/vpn/latest/s2svpn/VPNTunnels.html',
    recommended_action: 'Establish a successful VPN connection using IKE or IPsec configuration',
    apis: ['EC2:describeVpnConnections', 'STS:getCallerIdentity'],
    settings: {
        enable_vpn_tunnel_state: {
            name: 'Enable VPN Tunnel State',
            description: 'This is an opt-in plugin. This value should be set to true to enable this plugin',
            regex: '^(true|false)$',
            default: 'false'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var enable_vpn_tunnel_state = (settings.enable_vpn_tunnel_state || this.settings.enable_vpn_tunnel_state.default);

        if (!enable_vpn_tunnel_state || enable_vpn_tunnel_state == 'false') return callback(null, results, source);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ec2, function(region, rcb){
            var describeVpnConnections = helpers.addSource(cache, source,
                ['ec2', 'describeVpnConnections', region]);

            if (!describeVpnConnections) return rcb();

            if (describeVpnConnections.err || !describeVpnConnections.data) {
                helpers.addResult(results, 3,
                    `Unable to query for VPN connections: ${helpers.addError(describeVpnConnections)}`,
                    region);
                return rcb();
            }

            if (!describeVpnConnections.data.length) {
                helpers.addResult(results, 0,
                    'No VPN connections found', region);
                return rcb();
            }

            for (var vpn of describeVpnConnections.data) {
                if (!vpn.VpnConnectionId) continue;

                var resource = `arn:${awsOrGov}:ec2:${region}:${accountId}:vpn-connection/${vpn.VpnConnectionId}`;
                var tunnelDown = false;

                if (vpn.VgwTelemetry && vpn.VgwTelemetry.length) {
                    for (var vgw of vpn.VgwTelemetry) {
                        if (vgw.Status && vgw.Status.toUpperCase() === 'DOWN') {
                            tunnelDown = true;
                            break;
                        }
                    }
                } else {
                    helpers.addResult(results, 2,
                        `VPN connection "${vpn.VpnConnectionId}" does not have any tunnel configured`,
                        region, resource);
                    continue;
                }

                if (!tunnelDown) {
                    helpers.addResult(results, 0,
                        `VPN connection "${vpn.VpnConnectionId}" has all tunnels UP`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `VPN connection "${vpn.VpnConnectionId}" has tunnel down`,
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
