var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Open All Ports Protocols',
    category: 'Networking',
    description: 'Determine if security list has all ports or protocols open to the public',
    more_info: 'Security lists should be created on a per-service basis and avoid allowing all ports or protocols.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securitylists.htm',
    recommended_action: 'Modify the security list to specify a specific port and protocol to allow.',
    apis: ['vcn:list', 'vcn:get', 'publicIp:list', 'securityList:list'],
    compliance: {
        hipaa: 'HIPAA requires strict access controls to networks and services ' +
            'processing sensitive data. security lists are the built-in ' +
            'method for restricting access to OCI services and should be ' +
            'configured to allow least-privilege access.',
        pci: 'PCI has explicit requirements around firewalled access to systems. ' +
            'security lists should be properly secured to prevent access to ' +
            'backend services.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.vcn, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var vcn = helpers.addSource(cache, source,
                    ['vcn', 'list', region]);

                if (!vcn) return rcb();

                if (vcn.err || !vcn.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for VCNs: ' +
                        helpers.addError(vcn), region);
                    return rcb();
                }

                var ports = {
                    'all': []
                };

                var service = 'All Ports';

                var getSecurityLists = helpers.addSource(cache, source,
                    ['securityList', 'list', region]);

                if (!getSecurityLists) return rcb();

                if (getSecurityLists.err && getSecurityLists.err.length)  {
                    helpers.addResult(results, 3,
                        'Unable to query for security lists: ' +
                        helpers.addError(getSecurityLists), region);
                    return rcb();
                }

                if (!getSecurityLists.data || !getSecurityLists.data.length) {
                    helpers.addResult(results, 0,
                        'No security lists found', region);
                    return rcb();
                }

                helpers.findOpenPortsAll(getSecurityLists.data, ports,
                    service, region, results);
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};