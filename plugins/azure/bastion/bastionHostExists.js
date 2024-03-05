var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Azure Bastion Host Exists',
    category: 'Bastion',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensure that there is at least one Bastion host in Azure subscription.',
    more_info: 'Bastion provides secure RDP and SSH connectivity to all of the VMs in the virtual network in which it is provisioned. Using Azure Bastion protects your virtual machines from exposing RDP/SSH ports to the outside world, while still providing secure access using RDP/SSH.',
    recommended_action: 'Create an Azure Bastion Host in azure account.',
    link: 'https://learn.microsoft.com/en-us/azure/bastion/bastion-overview',
    apis: ['bastionHosts:listAll'],
    realtime_triggers: ['microsoftnetwork:bastionhosts:write','microsoftnetwork:bastionhosts:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.bastionHosts, function(location, rcb){
            let bastionHost = helpers.addSource(cache, source, 
                ['bastionHosts', 'listAll', location]);

            if (!bastionHost) return rcb();

            if (bastionHost.err || !bastionHost.data) {
                helpers.addResult(results, 3, 'Unable to query for bastion host: ' + helpers.addError(bastionHost), location);
                return rcb();
            }

            if (bastionHost.data.length) {
                helpers.addResult(results, 0, `There are ${bastionHost.data.length} Bastion hosts`, location);
            } else {
                helpers.addResult(results, 2, 'No Bastion hosts found', location);
            }
           
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
}; 