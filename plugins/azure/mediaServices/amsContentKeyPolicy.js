var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Media Services Content Key Policy',
    category: 'Media Services',
    domain: 'Content Delivery',
    severity: 'Low',
    description: 'Ensure that Azure Media Services have Content Key Policy configured.',
    more_info: 'A Content Key Policy in Azure Media Services dictates how content keys, ensuring secure asset access, are delivered to end clients. It allows setting requirements or restrictions that keys with specific configurations must meet before being delivered to clients.',
    link: 'https://learn.microsoft.com/en-us/azure/media-services/latest/drm-content-key-policy-concept',
    recommended_action: 'Modify Media Service account and add content key policy.',
    apis: ['mediaServices:listAll', 'mediaServices:listContentKeyPolicies'],
    realtime_triggers: ['microsoftmedia:mediaservices:write', 'microsoftmedia:mediaservices:delete','microsoftmedia:mediaservices:contentkeypolicies:write','microsoftmedia:mediaservices:contentkeypolicies:delete'],

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

                var listContentKeyPolicies = helpers.addSource(cache, source, 
                    ['mediaServices', 'listContentKeyPolicies', location, mediaService.id]);

                if (!listContentKeyPolicies || listContentKeyPolicies.err || !listContentKeyPolicies.data) {
                    helpers.addResult(results, 3, `Unable to query Content Key Policy for Media service account: ${helpers.addError(listContentKeyPolicies)}`,
                        location, mediaService.id);
                    continue;
                }
                if (listContentKeyPolicies.data.length) {
                    helpers.addResult(results, 0, 'Media Service account has content key policy configured', location, mediaService.id);
                } else {
                    helpers.addResult(results, 2, 'Media Service account does not have content key policy configured', location, mediaService.id);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};