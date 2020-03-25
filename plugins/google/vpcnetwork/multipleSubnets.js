var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Multiple Subnets',
    category: 'VPC Network',
    description: 'Ensures that VPCs have multiple networks to provide a layered architecture',
    more_info: 'A single network within a VPC increases the risk of a broader blast radius in the event of a compromise.',
    link: 'https://cloud.google.com/vpc/docs/vpc',
    recommended_action: 'Create multiple networks/subnets in each VPC and change the architecture to take advantage of public and private tiers.',
    apis: ['networks:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.networks, function(region, rcb){
            let networks = helpers.addSource(
                cache, source, ['networks', 'list', region]);

            if (!networks) return rcb();

            if (networks.err || !networks.data) {
                helpers.addResult(results, 3, 'Unable to query networks: ' + helpers.addError(networks), region);
                return rcb();
            }

            if (!networks.data.length) {
                helpers.addResult(results, 0, 'No networks found', region);
                return rcb();
            }
            var subnetRegions;
            networks.data.forEach(network => {
                regions = helpers.regions();
                var myRegions = {};
                var warnNetworks = [];
                var failNetworks = [];
                var passNetworks = [];
                var noNetworks = [];
                var subnets = network.subnetworks;

                subnetRegions = regions.zones;
                if (subnets) {
                    subnets.forEach(subnet => {
                        var splitSubnet = subnet.split('/');
                        subnetName = splitSubnet[10];
                        subnetRegion = splitSubnet[8];

                        if (subnetRegions.hasOwnProperty(subnetRegion) && subnetName != 'default') {
                            if (!myRegions[subnetRegion]) {
                                myRegions[subnetRegion] = 1;
                            } else {
                                myRegions[subnetRegion] += 1;
                            }

                        } else if (subnetRegions.hasOwnProperty(subnetRegion) && subnetName == 'default') {
                            myRegions[subnetRegion] = 0.5;

                        } else if (!subnetRegions.hasOwnProperty(subnetRegion) && subnetName == 'default') {
                            if (!myRegions[subnetRegion]) {
                                myRegions[subnetRegion] = .5;
                            } else {
                                myRegions[subnetRegion] += .5;
                            }


                        } else if (!subnetRegions.hasOwnProperty(subnetRegion) && subnetName != 'default') {
                            if (!myRegions[subnetRegion]) {
                                myRegions[subnetRegion] = 1;
                            } else {
                                myRegions[subnetRegion] += 1;
                            }

                        }
                    });
                }
                for (var sub in myRegions) {
                    if (Math.floor(myRegions[sub]) > 1) {
                        passNetworks.push(sub);
                    } else if (myRegions[sub] == 1) {
                        failNetworks.push(sub);
                    } else if (myRegions[sub] == .5) {
                        warnNetworks.push(sub);
                    } else if(myRegions[sub] == 0) {
                        noNetworks.push(sub);
                    }
                }

                if (passNetworks.length) {
                    var msg = 'There are ' + myRegions[sub] + ' different subnets used in these regions: ';
                    helpers.addResult(results, 0,
                        msg + passNetworks.join(', '), null, network.id);
                }
                if (failNetworks.length) {
                    var msg = 'Only one subnet in these regions is used: ';
                    helpers.addResult(results, 2,
                        msg + failNetworks.join(', '), null, network.id);
                }
                if (warnNetworks.length) {
                    var msg = 'Only the default subnet in these regions is used: ';
                    helpers.addResult(results, 2,
                        msg + warnNetworks.join(', '), null, network.id);
                }
                if (noNetworks.length) {
                    var msg = 'The VPC does not have any subnets in these regions: ';
                    helpers.addResult(results, 0,
                        msg + noNetworks.join(', '), null, network.id);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}