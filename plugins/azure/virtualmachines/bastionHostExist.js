var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Azure Bastion Host Exists',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensure that Azure Bastion Host exists.',
    more_info: 'Bastion provides secure RDP and SSH connectivity to all of the VMs in the virtual network in which it is provisioned. Using Azure Bastion protects your virtual machines from exposing RDP/SSH ports to the outside world, while still providing secure access using RDP/SSH.',
    recommended_action: 'Create an Azure Bastion Host in azure account.',
    link: 'https://docs.microsoft.com/en-us/azure/bastion/bastion-overview',
    apis: ['bastionHost:listAll'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.bastionHost, function(location, rcb){

            var bastionHost = helpers.addSource(cache, source, 
                    ['bastionHost', 'listAll', location]);

                if (!bastionHost) return rcb();

                if (bastionHost.err || !bastionHost.data) {
                    helpers.addResult(results, 3, 'Unable to query for bastion host: ' + helpers.addError(bastionHost), location);
                    return rcb();
                }

                if (bastionHost.data.length) {
                    helpers.addResult(results, 0, 'Azure bastion host exists', location, bastionHost.data[0].id);
                } else {
                    helpers.addResult(results, 2, 'Azure bastion host does not exist', location);
                }
           
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
}; 