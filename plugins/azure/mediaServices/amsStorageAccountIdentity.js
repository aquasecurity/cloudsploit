var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Media Services Storage Account Managed Identity',
    category: 'Media Services',
    domain: 'Content Delivery',
    severity: 'Medium',
    description: 'Ensures that Azure Media Service accounts have managed identity enabled for Storage Account authentication.',
    more_info: 'Enabling managed identity for storage authentication allows secure access to Azure Storage without explicit credentials, enhancing security and simplifying access management for Azure Media Services.',
    link: 'https://learn.microsoft.com/en-us/azure/media-services/latest/concept-managed-identities#media-services-managed-identity-scenarios',
    recommended_action: 'Modify Media Service storage account settings and enable managed identity.',
    apis: ['mediaServices:listAll'],
    realtime_triggers: ['microsoftmedia:mediaservices:write', 'microsoftmedia:mediaservices:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.mediaServices, function(location, rcb){
            var mediaServices = helpers.addSource(cache, source, 
                ['mediaServices', 'listAll', location]);

            if (!mediaServices) return rcb();

            if (mediaServices.err || !mediaServices.data) {
                helpers.addResult(results, 3, 'Unable to query for Media Services: ' + helpers.addError(mediaServices), location);
                return rcb();
            }

            if (!mediaServices.data.length) {
                helpers.addResult(results, 0, 'No existing Media Services found', location);
                return rcb();
            }

            for (let mediaService of mediaServices.data) {
                if (!mediaService.id) continue;

                if (mediaService.storageAuthentication && mediaService.storageAuthentication.toLowerCase() === 'managedidentity') {
                    helpers.addResult(results, 0, 'Media Service account has managed identity enabled for storage account authentication', location, mediaService.id);
                } else {
                    helpers.addResult(results, 2, 'Media Service account has managed identity disabled for storage account authentication', location, mediaService.id);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};