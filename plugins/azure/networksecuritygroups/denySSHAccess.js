const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Deny SSH Access',
    category: 'Network Security Groups',
    description: 'Ensures that all Network Security Group Security Rules deny public SSH access',
    more_info: 'Inbound security group rules should prohibit inbound SSH access from the global address.',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-restrict-access-through-internet-facing-endpoints',
    recommended_action: 'For each Network Security Group attached to a Virtual Machine instance, ensure that the inbound SSH port is appropriately restricted.',
    apis: ['resourceGroups:list', 'networkSecurityGroups:list', 'securityRules:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.securityRules, (location, rcb) => {
            const securityRules = helpers.addSource(cache, source, 
                ['securityRules', 'list', location]);
            
            if (!securityRules) return rcb();

            if (securityRules.err || !securityRules.data) {
                helpers.addResult(results, 3,
                    'Unable to query Security Rules: ' + helpers.addError(securityRules), location);
                return rcb();
            }

            if (!securityRules.data.length) {
                helpers.addResult(results, 0, 'No Security Rules found', location);
                return rcb();
            }

            let isExists = false;

            securityRules.data.forEach(securityRule => {
                if (securityRule.destinationPortRange) {
                    var portRange = securityRule.destinationPortRange.split(":");
                    let startPort = portRange[0];
                    let endPort = portRange[1];

                    if (securityRule.access &&
                        securityRule.access === "Allow" && 
                        securityRule.direction &&
                        securityRule.direction === "Inbound" &&
                        securityRule.protocol && 
                        securityRule.protocol == "TCP") {

                        if (securityRule.destinationPortRange &&
                            (securityRule.destinationPortRange === "22" || 
                            securityRule.destinationPortRange === "*" || 
                            securityRule.destinationPortRange.indexOf("22,") > -1 || 
                            (parseInt(startPort) <= 22 && parseInt(endPort) >= 22)) && 
                            securityRule.sourceAddressPrefix &&
                            (securityRule.sourceAddressPrefix === "0.0.0.0" || 
                            securityRule.sourceAddressPrefix === "<nw>/0" || 
                            securityRule.sourceAddressPrefix === "internet" || 
                            securityRule.sourceAddressPrefix == "*" || 
                            securityRule.sourceAddressPrefix == "any")) {

                            isExists = true;
                            helpers.addResult(results, 2,
                                'Security Rule allows public SSH access', location, securityRule.id);
                        }
                    }
                }
            });
                
            if(!isExists) {
                helpers.addResult(results, 0,
                    'There are no Security Rules that allow public SSH access', location);
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
