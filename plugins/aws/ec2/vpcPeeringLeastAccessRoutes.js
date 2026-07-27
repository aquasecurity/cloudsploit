var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'VPC Peering Least Access Routes',
    category: 'EC2',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensure routing tables for VPC peering are least access',
    more_info: 'Being highly selective in peering routing tables minimizes the impact of a breach, as resources outside of these routes are inaccessible to the peered VPC.',
    link: 'https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-routing.html',
    recommended_action: 'Replace broad VPC peering routes with more specific destination CIDR blocks',
    apis: ['EC2:describeRouteTables', 'EC2:describeVpcPeeringConnections', 'STS:getCallerIdentity'],
    realtime_triggers: ['ec2:CreateRoute', 'ec2:ReplaceRoute', 'ec2:DeleteRoute', 'ec2:CreateVpcPeeringConnection', 'ec2:DeleteVpcPeeringConnection'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var regions = helpers.regions(settings);
        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ec2, function(region, rcb) {
            var describeRouteTables = helpers.addSource(cache, source, ['ec2', 'describeRouteTables', region]);
            var describeVpcPeeringConnections = helpers.addSource(cache, source, ['ec2', 'describeVpcPeeringConnections', region]);

            if (!describeRouteTables || !describeVpcPeeringConnections) return rcb();

            if (describeRouteTables.err || !describeRouteTables.data) {
                helpers.addResult(results, 3,
                    'Unable to query for route tables: ' + helpers.addError(describeRouteTables), region);
                return rcb();
            }

            if (describeVpcPeeringConnections.err || !describeVpcPeeringConnections.data) {
                helpers.addResult(results, 3,
                    'Unable to query for VPC peering connections: ' + helpers.addError(describeVpcPeeringConnections), region);
                return rcb();
            }

            var peeringById = {};
            describeVpcPeeringConnections.data.forEach(function(peering) {
                peeringById[peering.VpcPeeringConnectionId] = peering;
            });

            var peeringRouteTables = 0;

            describeRouteTables.data.forEach(function(routeTable) {
                var peeringRoutes = getPeeringRoutes(routeTable.Routes);
                if (!peeringRoutes.length) return;

                peeringRouteTables++;
                var resource = `arn:${awsOrGov}:ec2:${region}:${accountId}:route-table/${routeTable.RouteTableId}`;
                var violations = [];

                peeringRoutes.forEach(function(route) {
                    var peeringId = route.VpcPeeringConnectionId || route.GatewayId;
                    var peerCidrs = getPeerCidrs(peeringById[peeringId], routeTable.VpcId);
                    var destinations = [];

                    if (route.DestinationCidrBlock) destinations.push(route.DestinationCidrBlock);
                    if (route.DestinationIpv6CidrBlock) destinations.push(route.DestinationIpv6CidrBlock);

                    destinations.forEach(function(destination) {
                        if (peerCidrs.indexOf(destination.toLowerCase()) > -1) {
                            violations.push(`${destination} via ${peeringId}: routes full peer VPC CIDR`);
                        }
                    });
                });

                if (violations.length) {
                    helpers.addResult(results, 2,
                        `Route table "${routeTable.RouteTableId}" has non-compliant VPC peering routes: ${violations.join('; ')}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 0,
                        `Route table "${routeTable.RouteTableId}" uses least-access VPC peering routes`,
                        region, resource);
                }
            });

            if (!peeringRouteTables) {
                helpers.addResult(results, 0, 'No VPC peering routes found', region);
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

function getPeeringRoutes(routes) {
    if (!routes || !routes.length) return [];

    return routes.filter(function(route) {
        return route.VpcPeeringConnectionId ||
            (route.GatewayId && route.GatewayId.indexOf('pcx-') === 0);
    });
}

function getPeerCidrs(peering, localVpcId) {
    var cidrs = [];

    if (!peering || !localVpcId) return cidrs;

    var requester = peering.RequesterVpcInfo || {};
    var accepter = peering.AccepterVpcInfo || {};
    var peerInfo;

    if (requester.VpcId === localVpcId) peerInfo = accepter;
    else if (accepter.VpcId === localVpcId) peerInfo = requester;

    if (!peerInfo) return cidrs;

    if (peerInfo.CidrBlock) cidrs.push(peerInfo.CidrBlock.toLowerCase());

    if (peerInfo.CidrBlockSet && peerInfo.CidrBlockSet.length) {
        peerInfo.CidrBlockSet.forEach(function(block) {
            if (block.CidrBlock && cidrs.indexOf(block.CidrBlock.toLowerCase()) === -1) {
                cidrs.push(block.CidrBlock.toLowerCase());
            }
        });
    }

    return cidrs;
}
