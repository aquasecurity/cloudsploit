const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Deny SSH Access',
    category: 'Network Security Groups',
    description: 'Ensure that all of Network Security Groups Security Rules deny public SSH access.',
    more_info: 'In order to deny ssh access to a Virtual Machine, inbound security rules must be configured to exclude public ssh access to the Virtual Machine.',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-restrict-access-through-internet-facing-endpoints',
    recommended_action: '1. Enter Network Security Groups. 2. Select the Network Security Group in question. 3. Enter the inbound rules blade. 4. Remove the rule that allows SSH.',
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
                helpers.addResult(results, 0, 'No existing Security Rules', location);
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
                            'the Security Rule allows public SSH access.', location, securityRule.id);
                        };
                    }; 
                };
            });
                
            if(!isExists) {
                helpers.addResult(results, 0,
                    'There is no Security Rule that allows public SSH access.', location);
            };

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
