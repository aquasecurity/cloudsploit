var util = require('util');
var async = require('async');

var helpers = require('../../../helpers/azure/');

var ACL_ALL_USERS = 'http://acs.amazonaws.com/groups/global/AllUsers';
var ACL_AUTHENTICATED_USERS = 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers';

module.exports = {
    title: 'Resource Groups',
    category: 'Resource Groups',
    description: 'Ensures Resource Groups ...',
    more_info: 'Resource Groups can be configured to ...',
    recommended_action: 'Disable Resource Groups ...policies ...',
    link: 'https://docs.microsoft.com/en-us/azure/azure-resource-manager/',
    apis: ['resourceGroups:list'],

    run: function(cache, settings, callback) {
		var results = [];
		var source = {};
		var locations = helpers.locations(settings.govcloud);

		async.each(locations.resourcegroups, function(location, rcb){
			var resourceGroups = helpers.addSource(cache, source,
				['resourcegroups', 'list', location]);

			if (!resourceGroups) return rcb();

			if (resourceGroups.err || !resourceGroups.data) {
				helpers.addResult(results, 3,
					'Unable to query Resource Groups: ' + helpers.addError(resourceGroups), location);
				return rcb();
			}

			if (!resourceGroups.data.length) {
				helpers.addResult(results, 2, 'No existing resource groups', location);
			} else {
				for (res in resourceGroups.data) {
					var resourceGroup = resourceGroups.data[res];

					if (resourceGroup.properties.provisioningState=="Succeeded") {
						helpers.addResult(results, 0, 'The resource group is properly provisioned', location, resourceGroup.id);
					} else {
						helpers.addResult(results, 2, 'This resource group is not provisioned', location, resourceGroup.id);
					}
				}
			}
			rcb();
		}, function(){
			// Global checking goes here
			callback(null, results, source);
		});
    }
};