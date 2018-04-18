var async = require('async');
var helpers = require('../../helpers');

module.exports = {
    title: 'Cross VPC Public Private Communication',
    category: 'EC2',
    description: 'Ensures communication between public and private VPC tiers is not enabled',
    more_info: 'Communication between the public tier of one VPC and the private tier of other VPCs should never be allowed. Instead, VPC peerings with proper NACLs and gateways should be used',
    link: 'https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Subnets.html',
    recommended_action: 'Remove the NACL rules allowing communication between the public and private tiers of different VPCs',
    apis: ['EC2:describeSubnets', 'EC2:describeRouteTables', 'EC2:describeVpcPeeringConnections'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};


        async.each(helpers.regions.ec2, function(region, rcb) {


                // for Subnets
                var describeSubnets = helpers.addSource(cache, source, ['ec2', 'describeSubnets', region]);

                // error handling
                if (!describeSubnets || !describeSubnets.data || describeSubnets.err) {
                    helpers.addResult(results, 3, 'Unable to query for Subnets: ' + helpers.addError(describeSubnets), region);
                }

                // grapping a list of Vpcs and Subnets
                var subVpc = [];
                for (i in describeSubnets.data) {
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
                }


                // for VpcPeeringConnections
                var describeVpcPeeringConnections = helpers.addSource(cache, source, ['ec2', 'describeVpcPeeringConnections', region]);

                // error handling
                if (!describeVpcPeeringConnections || !describeVpcPeeringConnections.data || describeVpcPeeringConnections.err) {
                    helpers.addResult(results, 3, 'Unable to query for VpcPeering: ' + helpers.addError(describeRouteTables), region);
                }

                if (!describeVpcPeeringConnections.data.length) {
                    helpers.addResult(results, 0, 'No public private subnets connection found', region);
                }

                // collecting data about the peering connections
                var vpcPeeringInfo = [];

                for (i in describeVpcPeeringConnections.data) {
                    vpcPeeringInfo.push({
                        peeringId: describeVpcPeeringConnections.data[i].VpcPeeringConnectionId,
                        vpcId: describeVpcPeeringConnections.data[i].AccepterVpcInfo.VpcId,
                        peercidr: describeVpcPeeringConnections.data[i].AccepterVpcInfo.CidrBlock
                    });
                    vpcPeeringInfo.push({
                        peeringId: describeVpcPeeringConnections.data[i].VpcPeeringConnectionId,
                        vpcId: describeVpcPeeringConnections.data[i].RequesterVpcInfo.VpcId,
                        peercidr: describeVpcPeeringConnections.data[i].RequesterVpcInfo.CidrBlock
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
                for (k in describeRouteTables.data) {
                    routes.push({
                        rtId: describeRouteTables.data[k].RouteTableId,
                        type: 'private'
                    });
                    for (l in describeRouteTables.data[k].Routes) {
                        routesInfo.push({
                            rtId: describeRouteTables.data[k].RouteTableId,
                            rtCB: describeRouteTables.data[k].Routes[l].DestinationCidrBlock,
                            rtIg: describeRouteTables.data[k].Routes[l].GatewayId,
                            rtVpcId: describeRouteTables.data[k].Routes[l].VpcPeeringConnectionId
                        });
                    }
                    for (i in describeRouteTables.data[k].Associations) {
                        routesInfo.push({
                            rtId: describeRouteTables.data[k].RouteTableId,
                            rtSub: describeRouteTables.data[k].Associations[i].SubnetId
                        });
                    }
                }

                // filtering the public RouteTables
                for (i in routes) {
                    for (j in routesInfo) {
                        if (routes[i].rtId == routesInfo[j].rtId && routesInfo[j].rtCB == '0.0.0.0/0' && routesInfo[j].rtIg != 'local') {
                            routes[i].type = 'public';
                            publicRoutes.push(routes[i].rtId);
                        }
                    }
                }
                for (i in routes) {
                    if (routes[i].type == 'private') {
                        privateRoutes.push(routes[i].rtId);
                    }
                }

                // filtering the public and private subnets based on the RouteTables
                for (i in publicRoutes) {
                    for (j in routesInfo) {
                        if (publicRoutes[i] == routesInfo[j].rtId) {
                            tempPubSubnets.push(routesInfo[j].rtSub);
                        }
                    }
                }
                for (i in privateRoutes) {
                    for (j in routesInfo) {
                        if (privateRoutes[i] == routesInfo[j].rtId) {
                            tempPrvSubnets.push(routesInfo[j].rtSub);
                        }
                    }
                }


                // mapping the subnets into one dictionary
                for (i in subVpc) {
                    for (j in tempPrvSubnets) {
                        if (subVpc[i].subId == tempPrvSubnets[j]) {
                            subnets.push({
                                subId: subVpc[i].subId,
                                subCidr: subVpc[i].subCidr,
                                subVpcId: subVpc[i].vcpId,
                                type: 'private'
                            });
                        }
                    }
                }
                for (i in subVpc) {
                    for (j in tempPubSubnets) {
                        if (subVpc[i].subId == tempPubSubnets[j]) {
                            subnets.push({
                                subId: subVpc[i].subId,
                                subCidr: subVpc[i].subCidr,
                                subVpcId: subVpc[i].vcpId,
                                type: 'public'
                            });
                        }
                    }
                }

                // filtering the routes that are related to the peering process
                var peeringRoutes = [];

                for (i in vpcPeeringInfo) {
                    for (j in routesInfo) {
                        if (vpcPeeringInfo[i].peeringId == routesInfo[j].rtVpcId) {
                            peeringRoutes.push({
                                routeId: routesInfo[j].rtId,
                                vpcId: vpcPeeringInfo[i].vpcId,
                                peeringCidr: routesInfo[j].rtCB,
                                peeringId: vpcPeeringInfo[i].peeringId
                            });
                        }
                    }
                }

                // generating the public and private records
                var pubRecord = [];
                var prvRecord = [];

                for (i in peeringRoutes) {
                    for (j in subnets) {
                        if (peeringRoutes[i].vpcId == subnets[j].subVpcId && peeringRoutes[i].peeringCidr == subnets[j].subCidr) {
                            if (subnets[j].type == 'public') {
                                pubRecord.push({
                                    vpcId: peeringRoutes[i].vpcId,
                                    peeringId: peeringRoutes[i].peeringId,
                                    subnetId: subnets[j].subId
                                });
                            } else {
                                prvRecord.push({
                                    vpcId: peeringRoutes[i].vpcId,
                                    peeringId: peeringRoutes[i].peeringId,
                                    subnetId: subnets[j].subId
                                });
                            }
                        }
                    }
                }

                // comparing and showing the results
                for (i in pubRecord) {
                    for (j in prvRecord) {
                        if (pubRecord[i].peeringId == prvRecord[j].peeringId) {
                            helpers.addResult(results, 2, 'Public-Private cross vpc subnet connection found, for Subnets: ' + pubRecord[i].subnetId + ' and ' + prvRecord[j].subnetId, region);
                        }
                    }
                }

                return rcb();
            },
            function() {
                callback(null, results, source);
            });
    }
};
