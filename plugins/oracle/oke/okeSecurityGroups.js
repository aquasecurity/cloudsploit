var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'OKE Security Groups',
    category: 'OKE',
    domain: 'Containers',
    severity: 'Medium',
    description: 'Ensures the OKE clusters only allows inbound traffic on port 443.',
    more_info: 'The OKE clusters only requires port 443 access. Security groups for the clusters should not add additional port access.',
    link: 'https://docs.oracle.com/en-us/iaas/Content/Security/Reference/oke_security.htm',
    recommended_action: 'Configure security groups for the OKE clusters to allow access only on port 443.',
    apis: ['vcn:list', 'cluster:list', 'networkSecurityGroup:list', 'securityRule:list'],
   
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.cluster, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var clusters = helpers.addSource(cache, source,
                    ['cluster', 'list', region]);

                if (!clusters) return rcb();

                if (clusters.err || !clusters.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for OKE clusters: ' + helpers.addError(clusters), region);
                    return rcb();
                }

                if (!clusters.data.length) {
                    helpers.addResult(results, 0, 'No OKE clusters found', region);
                    return rcb();
                }

                var securityGroups = helpers.addSource(cache, source,
                    ['networkSecurityGroup', 'list', region]);

                if (!securityGroups || securityGroups.err || !securityGroups.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for network security groups: ' + helpers.addError(securityGroups), region);
                    return rcb();

                }

                var securityRules = helpers.addSource(cache, source,
                    ['securityRule', 'list', region]);

                if (!securityRules || securityRules.err || !securityRules.data)  {
                    helpers.addResult(results, 3,
                        'Unable to query for security rules: ' + helpers.addError(securityRules), region);
                    return rcb();

                }

                securityGroups.data.forEach(securityGroup => {
                    if (securityRules && securityRules.data.find(securityRule => securityRule.networkSecurityGroups === securityGroup.id)) {
                        securityGroup.securityRules = securityRules.data.filter(securityRule => securityRule.networkSecurityGroups === securityGroup.id);
                    }
                });

                clusters.data.forEach(cluster => {
                    if (!cluster.vcnId) return;
                    
                    var allowsOtherPorts = false;
                    const clusterSecurityGroups = securityGroups.data.filter(securityGroup => securityGroup.vcnId === cluster.vcnId);
                    
                    clusterSecurityGroups.forEach(group => {

                        if (!group.securityRules || !group.securityRules.length) {
                            allowsOtherPorts = true;
                            return;
                        }

                        if (group.securityRules) {
                            group.securityRules.map(rule => {
                                if (rule.direction === 'INGRESS') {
                                    var ruleOptions = rule.tcpOptions || rule.udpOptions;
                                    if (!ruleOptions) {
                                        allowsOtherPorts = true;
                                    } else if (ruleOptions.sourcePortRange
                                        && ruleOptions.sourcePortRange.max && ruleOptions.sourcePortRange.max != 443
                                        && ruleOptions.sourcePortRange.minf && ruleOptions.sourcePortRange.minf != 443
                                        && ruleOptions.destinationPortRange
                                        && ruleOptions.destinationPortRange.max && ruleOptions.destinationPortRange.max != 443
                                        && ruleOptions.destinationPortRange.minf && ruleOptions.destinationPortRange.minf != 443
                                    ) {
                                        allowsOtherPorts = true;
                                    }
                                }
                            }
                            );
                        }
                    });

                    if (allowsOtherPorts) {
                        helpers.addResult(results, 2, 'OKE cluster security groups allow additional access on unnecessary ports', region, cluster.id);
                    } else {
                        helpers.addResult(results, 0, 'OKE cluster security groups do not allow additional access on unnecessary ports', region, cluster.id);
                    }
                });
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};


       