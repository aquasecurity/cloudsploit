var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'VPC Peering Least Access Routes',
    category: 'EC2',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensures VPC peering route table entries follow a configurable least-access routing policy',
    more_info: 'VPC peering routes should be scoped to the minimum destination CIDR blocks required. Use plugin settings to define the maximum allowed route breadth for your environment.',
    link: 'https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-routing.html',
    recommended_action: 'Replace broad VPC peering routes with more specific destination CIDR blocks',
    apis: ['EC2:describeRouteTables', 'EC2:describeVpcPeeringConnections', 'STS:getCallerIdentity'],
    settings: {
        max_peering_route_prefix_length: {
            name: 'Max Peering Route Prefix Length',
            description: 'Minimum required prefix length for peering route destinations (e.g. 24 allows /24-/32 and fails on /16)',
            regex: '^([0-9]|[1-2][0-9]|3[0-2])$',
            default: ''
        },
        allowed_peering_destinations: {
            name: 'Allowed Peering Destinations',
            description: 'Comma-separated destination CIDR blocks permitted on VPC peering routes',
            regex: '[0-9./:,a-fA-F-]',
            default: ''
        },
        fail_on_full_vpc_cidr: {
            name: 'Fail on Full VPC CIDR Peering Routes',
            description: 'When true, fail peering routes whose destination equals the entire peer VPC CIDR block',
            regex: '^(true|false)$',
            default: 'true'
        }
    },
    compliance: {
        cis1: '4.4 Ensure routing tables for VPC peering are "least access"',
        cis2: '6.6 Ensure routing tables for VPC peering are "least access"'
    },
    realtime_triggers: ['ec2:CreateRoute', 'ec2:ReplaceRoute', 'ec2:DeleteRoute', 'ec2:CreateVpcPeeringConnection', 'ec2:DeleteVpcPeeringConnection'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var config = {
            maxPrefix: settings.max_peering_route_prefix_length || this.settings.max_peering_route_prefix_length.default,
            allowedDestinations: settings.allowed_peering_destinations || this.settings.allowed_peering_destinations.default,
            failOnFullVpcCidr: settings.fail_on_full_vpc_cidr || this.settings.fail_on_full_vpc_cidr.default
        };

        config.failOnFullVpcCidr = (config.failOnFullVpcCidr === 'true');
        config.allowedDestinations = config.allowedDestinations ?
            config.allowedDestinations.split(',').map(function(cidr) { return cidr.trim().toLowerCase(); }).filter(Boolean) :
            [];

        if (!config.maxPrefix && !config.allowedDestinations.length && !config.failOnFullVpcCidr) {
            return callback(null, results, source);
        }

        if (config.maxPrefix) config.maxPrefix = Number(config.maxPrefix);

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
                    var peering = peeringById[peeringId];
                    var destinations = [];

                    if (route.DestinationCidrBlock) destinations.push(route.DestinationCidrBlock);
                    if (route.DestinationIpv6CidrBlock) destinations.push(route.DestinationIpv6CidrBlock);

                    destinations.forEach(function(destination) {
                        var issue = evaluateRoute(destination, config, peering, routeTable.VpcId);
                        if (issue) {
                            violations.push(`${destination} via ${peeringId}: ${issue}`);
                        }
                    });
                });

                if (violations.length) {
                    helpers.addResult(results, 2,
                        `Route table "${routeTable.RouteTableId}" has non-compliant VPC peering routes: ${violations.join('; ')}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 0,
                        `Route table "${routeTable.RouteTableId}" uses least-access VPC peering routes per configured policy`,
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

function getPrefixLength(cidr) {
    if (!cidr || cidr.indexOf('/') === -1) return null;

    var prefix = parseInt(cidr.split('/')[1], 10);
    return isNaN(prefix) ? null : prefix;
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

function evaluateRoute(destination, config, peering, localVpcId) {
    var normalizedDestination = destination.toLowerCase();
    var issues = [];

    if (config.allowedDestinations.length &&
        config.allowedDestinations.indexOf(normalizedDestination) === -1) {
        issues.push('destination not in allowed_peering_destinations');
    }

    if (config.maxPrefix) {
        var prefixLength = getPrefixLength(normalizedDestination);
        if (prefixLength === null || prefixLength < config.maxPrefix) {
            issues.push(`destination broader than /${config.maxPrefix}`);
        }
    }

    if (config.failOnFullVpcCidr) {
        var peerCidrs = getPeerCidrs(peering, localVpcId);
        if (peerCidrs.indexOf(normalizedDestination) > -1) {
            issues.push('destination equals full peer VPC CIDR');
        }
    }

    return issues.length ? issues.join(', ') : null;
}
