var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Multiple Subnets',
    category: 'VPC Network',
    description: 'Ensures that VPCs have multiple networks to provide a layered architecture',
    more_info: 'A single network within a VPC increases the risk of a broader blast radius in the event of a compromise.',
    link: 'https://cloud.google.com/vpc/docs/vpc',
    recommended_action: 'Create multiple networks/subnets in each VPC and change the architecture to take advantage of public and private tiers.',
    apis: ['networks:list', 'projects:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.networks, function(region, rcb){
            let networks = helpers.addSource(
                cache, source, ['networks', 'list', region]);

            if (!networks) return rcb();

            if (networks.err || !networks.data) {
                helpers.addResult(results, 3, 'Unable to query networks: ' + helpers.addError(networks), region, null, null, networks.err);
                return rcb();
            }

            if (!networks.data.length) {
                helpers.addResult(results, 0, 'No networks found', region);
                return rcb();
            }

            let projects = helpers.addSource(cache, source,
                ['projects','get', 'global']);
    
            if (!projects || projects.err || !projects.data || !projects.data.length) {
                helpers.addResult(results, 3,
                    'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
                return callback(null, results, source);
            }
    
            var project = projects.data[0].name;

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
                if (subnets && subnets.length) {
                    subnets.forEach(subnet => {
                        var splitSubnet = subnet.split('/');
                        var subnetName = splitSubnet[10];
                        var subnetRegion = splitSubnet[8];

                        if (subnetRegions[subnetRegion] && subnetName != 'default') {
                            if (!myRegions[subnetRegion]) {
                                myRegions[subnetRegion] = 1;
                            } else {
                                myRegions[subnetRegion] += 1;
                            }

                        } else if (subnetRegions[subnetRegion] && subnetName == 'default') {
                            myRegions[subnetRegion] = 0.5;

                        } else if (!subnetRegions[subnetRegion] && subnetName == 'default') {
                            if (!myRegions[subnetRegion]) {
                                myRegions[subnetRegion] = .5;
                            } else {
                                myRegions[subnetRegion] += .5;
                            }


                        } else if (!subnetRegions[subnetRegion] && subnetName != 'default') {
                            if (!myRegions[subnetRegion]) {
                                myRegions[subnetRegion] = 1;
                            } else {
                                myRegions[subnetRegion] += 1;
                            }

                        }
                    });
                } else {
                    noNetworks.push(1);
                }
                for (var sub in myRegions) {
                    if (Math.floor(myRegions[sub]) > 1) {
                        passNetworks.push(sub);
                    } else if (myRegions[sub] == 1) {
                        failNetworks.push(sub);
                    } else if (myRegions[sub] == .5) {
                        warnNetworks.push(sub);
                    }
                }

                let resource = helpers.createResourceName('networks', network.name, project, 'global');
                if (passNetworks.length) {
                    let msg = 'There are ' + myRegions[sub] + ' different subnets used in these regions: ';
                    helpers.addResult(results, 0,
                        msg + passNetworks.join(', '), null, resource);
                }
                if (failNetworks.length) {
                    let msg = 'Only one subnet in these regions is used: ';
                    helpers.addResult(results, 2,
                        msg + failNetworks.join(', '), null, resource);
                }
                if (warnNetworks.length) {
                    let msg = 'Only the default subnet in these regions is used: ';
                    helpers.addResult(results, 2,
                        msg + warnNetworks.join(', '), null, resource);
                }
                if (noNetworks.length) {
                    let msg = 'The VPC does not have any subnets';
                    helpers.addResult(results, 0,
                        msg, null, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};