const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Open UDP Ports',
    category: 'Network Security Groups',
    domain: 'Network Access Control',
    severity: 'Medium',
    description: 'Ensures that Internet exposed UDP ports on network security groups are disabled.',
    more_info: 'The potential security problem with broadly exposing UDP services over the Internet is that attackers can use DDoS amplification techniques to reflect spoofed UDP traffic from Azure Virtual Machines. The most common types of these attacks use exposed DNS, NTP, SSDP, SNMP, CLDAP and other UDP-based services as amplification source for disrupting services of other machines on the Azure Virtual Network or even attack networked devices outside of Azure.',
    link: 'https://learn.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-network-security#ns-1-implement-security-for-internal-traffic',
    recommended_action: 'Disable direct UDP access to your Azure Virtual Machines from the Internet',
    apis: ['networkSecurityGroups:listAll'],
    realtime_triggers: ['microsoftnetwork:networksecuritygroups:write','microsoftnetwork:networksecuritygroups:delete','microsoftnetwork:networksecuritygroups:securityrules:write','microsoftnetwork:networksecuritygroups:securityrules:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.networkSecurityGroups, function(location, rcb) {

            let networkSecurityGroups = helpers.addSource(
                cache, source, ['networkSecurityGroups', 'listAll', location]
            );

            if (!networkSecurityGroups) return rcb();

            if (networkSecurityGroups.err || !networkSecurityGroups.data) {
                helpers.addResult(results, 3, 
                    'Unable to query for Network Security Groups: ' + helpers.addError(networkSecurityGroups), location);
                return rcb();
            }

            if (!networkSecurityGroups.data.length) {
                helpers.addResult(results, 0, 'No security groups found', location);
                return rcb();
            }

            for (let s in networkSecurityGroups.data) {
                var sg = networkSecurityGroups.data[s];
                let openUdpPorts = false;
                if (sg.securityRules &&
                    sg.securityRules.length) {
                    let InvalidSourceAddressPrefixes = ['*', '0.0.0.0', '<nw>/0', '/0', 'internet', 'any'];

                    var accessRules = sg.securityRules.filter((rule) => {
                        return (rule.properties &&
                            rule.properties.access &&
                            rule.properties.access.toLowerCase() == 'allow' &&
                            rule.properties.direction.toLowerCase() === 'inbound' &&
                            rule.properties.protocol.toLowerCase() === 'udp');
                    });

                    for (var rule in accessRules) {
                        if (!accessRules[rule].properties) continue;

                        let dRule = accessRules[rule].properties;

                        if (dRule.sourceAddressPrefix &&
                            InvalidSourceAddressPrefixes.indexOf(dRule.sourceAddressPrefix) > -1) {
                            openUdpPorts = true;
                        }
                    }

                    if (openUdpPorts) {
                        helpers.addResult(results, 2,
                            'The security group: ' + sg.name + ' has open UDP ports for internet access', location, sg.id);
                    } else {
                        helpers.addResult(results, 0,
                            'The security group: ' + sg.name + ' does not have open UDP ports for internet access', location, sg.id);
                    }
                } else {
                    helpers.addResult(results, 0,
                        'The security group: ' + sg.name + ' does not have any security rules', location, sg.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};