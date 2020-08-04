var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Cross VPC Public Private Communication',
    category: 'EC2',
    description: 'Ensures communication between public and private VPC tiers is not enabled',
    more_info: 'Communication between the public tier of one VPC and the private tier of other VPCs should never be allowed. Instead, VPC peerings with proper NACLs and gateways should be used',
    link: 'https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Subnets.html',
    recommended_action: 'Remove the NACL rules allowing communication between the public and private tiers of different VPCs',
    apis: ['EC2:describeSubnets', 'EC2:describeRouteTables', 'EC2:describeVpcPeeringConnections'],
    compliance: {
        pci: 'VPCs provide a firewall for compute resources that meets the network ' +
             'segmentation criteria for PCI. However, VPCs can be configured to ' +
             'communicate across these segmented boundaries. Ensure that public ' +
             'services in one VPC cannot communicate with the private tier of another.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ec2, function(region, rcb) {
            // for Subnets
            var describeSubnets = helpers.addSource(cache, source, ['ec2', 'describeSubnets', region]);

            // error handling
            if (!describeSubnets || !describeSubnets.data || describeSubnets.err) {
                helpers.addResult(results, 3, 'Unable to query for Subnets: ' + helpers.addError(describeSubnets), region);
                return rcb();
            }

            // grapping a list of Vpcs and Subnets
            var subVpc = [];
            for (var i in describeSubnets.data) {
                subVpc.push({
                    vcpId: describeSubnets.data[i].VpcId,
                    subId: describeSubnets.data[i].SubnetId,
                    subCidr: describeSubnets.data[i].CidrBlock
                });
            }

            // for RouteTables
            var describeRouteTables = helpers.addSource(cache, source, ['ec2', 'describeRouteTables', region]);

            // error handling
            if (!describeRouteTables || !describeRouteTables.data || describeRouteTables.err) {
                helpers.addResult(results, 3, 'Unable to query for RouteTables: ' + helpers.addError(describeRouteTables), region);
                return rcb();
            }

            // for VpcPeeringConnections
            var describeVpcPeeringConnections = helpers.addSource(cache, source, ['ec2', 'describeVpcPeeringConnections', region]);

            // error handling
            if (!describeVpcPeeringConnections || !describeVpcPeeringConnections.data || describeVpcPeeringConnections.err) {
                helpers.addResult(results, 3, 'Unable to query for VpcPeering: ' + helpers.addError(describeVpcPeeringConnections), region);
                return rcb();
            }

            if (!describeVpcPeeringConnections.data.length) {
                helpers.addResult(results, 0, 'No public private subnets connection found', region);
                return rcb();
            }

            // collecting data about the peering connections
            var vpcPeeringInfo = [];

            for (i in describeVpcPeeringConnections.data) {
                vpcPeeringInfo.push({
                    peeringId: describeVpcPeeringConnections.data[i].VpcPeeringConnectionId,
                    vpcId: describeVpcPeeringConnections.data[i].AccepterVpcInfo.VpcId,
                    peercidr: describeVpcPeeringConnections.data[i].AccepterVpcInfo.CidrBlock,
                    ownerId: describeVpcPeeringConnections.data[i].AccepterVpcInfo.OwnerId
                });
                vpcPeeringInfo.push({
                    peeringId: describeVpcPeeringConnections.data[i].VpcPeeringConnectionId,
                    vpcId: describeVpcPeeringConnections.data[i].RequesterVpcInfo.VpcId,
                    peercidr: describeVpcPeeringConnections.data[i].RequesterVpcInfo.CidrBlock,
                    ownerId: describeVpcPeeringConnections.data[i].RequesterVpcInfo.OwnerId
                });
            }


            var routes = [];
            var publicRoutes = [];
            var privateRoutes = [];
            var routesInfo = [];
            var tempPubSubnets = [];
            var tempPrvSubnets = [];
            var subnets = [];

            // collecting data about the Routes
            for (var k in describeRouteTables.data) {
                routes.push({
                    rtId: describeRouteTables.data[k].RouteTableId,
                    type: 'private'
                });
                for (var l in describeRouteTables.data[k].Routes) {
                    routesInfo.push({
                        rtId: describeRouteTables.data[k].RouteTableId,
                        rtCB: describeRouteTables.data[k].Routes[l].DestinationCidrBlock,
                        rtIg: describeRouteTables.data[k].Routes[l].GatewayId,
                        rtVpcId: describeRouteTables.data[k].Routes[l].VpcPeeringConnectionId
                    });
                }
                for (var m in describeRouteTables.data[k].Associations) {
                    routesInfo.push({
                        rtId: describeRouteTables.data[k].RouteTableId,
                        rtSub: describeRouteTables.data[k].Associations[m].SubnetId
                    });
                }
            }

            // filtering the public RouteTables
            for (var n in routes) {
                for (var o in routesInfo) {
                    if (routes[n].rtId == routesInfo[o].rtId && routesInfo[o].rtCB == '0.0.0.0/0' && routesInfo[o].rtIg != 'local') {
                        routes[n].type = 'public';
                        publicRoutes.push(routes[n].rtId);
                    }
                }
            }
            for (var p in routes) {
                if (routes[p].type == 'private') {
                    privateRoutes.push(routes[p].rtId);
                }
            }

            // filtering the public and private subnets based on the RouteTables
            for (var q in publicRoutes) {
                for (var r in routesInfo) {
                    if (publicRoutes[q] == routesInfo[r].rtId) {
                        tempPubSubnets.push(routesInfo[r].rtSub);
                    }
                }
            }
            for (var s in privateRoutes) {
                for (var t in routesInfo) {
                    if (privateRoutes[s] == routesInfo[t].rtId) {
                        tempPrvSubnets.push(routesInfo[t].rtSub);
                    }
                }
            }

            // mapping the subnets into one dictionary
            for (var u in subVpc) {
                for (var v in tempPrvSubnets) {
                    if (subVpc[u].subId == tempPrvSubnets[v]) {
                        subnets.push({
                            subId: subVpc[u].subId,
                            subCidr: subVpc[u].subCidr,
                            subVpcId: subVpc[u].vcpId,
                            type: 'private'
                        });
                    }
                }
            }
            for (var w in subVpc) {
                for (var x in tempPubSubnets) {
                    if (subVpc[w].subId == tempPubSubnets[x]) {
                        subnets.push({
                            subId: subVpc[w].subId,
                            subCidr: subVpc[w].subCidr,
                            subVpcId: subVpc[w].vcpId,
                            type: 'public'
                        });
                    }
                }
            }

            // filtering the routes that are related to the peering process
            var peeringRoutes = [];

            for (var y in vpcPeeringInfo) {
                for (var z in routesInfo) {
                    if (vpcPeeringInfo[y].peeringId == routesInfo[z].rtVpcId) {
                        peeringRoutes.push({
                            routeId: routesInfo[z].rtId,
                            vpcId: vpcPeeringInfo[y].vpcId,
                            peeringCidr: routesInfo[z].rtCB,
                            peeringId: vpcPeeringInfo[y].peeringId,
                            ownerId: vpcPeeringInfo[y].ownerId
                        });
                    }
                }
            }

            // generating the public and private records
            var pubRecord = [];
            var prvRecord = [];

            for (var a in peeringRoutes) {
                for (var b in subnets) {
                    if (peeringRoutes[a].vpcId == subnets[b].subVpcId && peeringRoutes[a].peeringCidr == subnets[b].subCidr) {
                        if (subnets[b].type == 'public') {
                            pubRecord.push({
                                vpcId: peeringRoutes[a].vpcId,
                                peeringId: peeringRoutes[a].peeringId,
                                subnetId: subnets[b].subId,
                                ownerId: peeringRoutes[a].ownerId
                            });
                        } else {
                            prvRecord.push({
                                vpcId: peeringRoutes[a].vpcId,
                                peeringId: peeringRoutes[a].peeringId,
                                subnetId: subnets[b].subId,
                                ownerId: peeringRoutes[a].ownerId
                            });
                        }
                    }
                }
            }

            // comparing and showing the results
            var register = 0;
            for (var c in pubRecord) {
                for (var d in prvRecord) {
                    if (pubRecord[c].peeringId == prvRecord[d].peeringId) {
                        register++;
                        helpers.addResult(results, 2, 'A route between public and private subnets of different VPCs found, for Subnets: ' + pubRecord[c].subnetId + ' and ' + prvRecord[d].subnetId, region, 'arn:aws:ec2:' + region + ':' + prvRecord[d].ownerId + ':vpc-peering-connection/' + prvRecord[d].peeringId);
                    }
                }
            }

            if (!register) {
                helpers.addResult(results, 0, 'No routes between public and private subnets of different VPCs found', region);
            }

            return rcb();
        },
        function() {
            callback(null, results, source);
        });
    }
};