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
    apis: ['bastionHost:listAll', 'subscriptions:listSubscriptions'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.bastionHost, function(location, rcb){


            var subscription = helpers.addSource(cache, source, 
                ['subscriptions', 'listSubscriptions', location]);

            if (!subscription) return rcb();

            if (subscription.err || !subscription.data) {
                helpers.addResult(results, 3, 'Unable to query for subscriptions: ' + helpers.addError(subscription), location);
                return rcb();
            }

            if (!subscription.data.length) {
                helpers.addResult(results, 0, 'No Azure subscription exist', location);
                return rcb();
            }

            for (let sub of subscription.data){

                if (!sub.id) continue;

                var bastionHost = helpers.addSource(cache, source, 
                    ['bastionHost', 'listAll', location, sub.id]);

                if (!bastionHost) continue;

                if (bastionHost.err || !bastionHost.data) {
                    helpers.addResult(results, 3, 'Unable to query for bastion host: ' + helpers.addError(bastionHost), location);
                    continue;
                }

                if (bastionHost.data.length) {
                    helpers.addResult(results, 0, 'Azure subscription have bastion host', location, sub.id);
                } else {
                    helpers.addResult(results, 2, 'Azure subscription does not have bastion host', location, sub.id);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
}; 