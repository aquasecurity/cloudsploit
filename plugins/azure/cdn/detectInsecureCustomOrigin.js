const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Detect Insecure Custom Origin',
    category: 'CDN',
    description: 'Ensure that HTTPS is enabled when creating a new CDN endpoint with a Custom Origin.',
    more_info: 'Detects if HTTPS is disabled for CDN endpoint of custom origins.',
    recommended_action: '1. Navigate to CDN profiles. 2. Select a profile. 3. Select an endpoint. 4. Select Settings > Origin. 5. Turn off HTTP and make sure HTTPS is turned on.',
    link: 'https://docs.microsoft.com/en-us/azure/cdn/cdn-create-endpoint-how-to',
    apis: ['resourceGroups:list', 'profiles:list', 'endpoints:listByProfile', 'origins:listByEndpoint'],
    compliance: {
        hipaa: 'HIPAA requires all data to be transmitted over secure channels. ' +
                'Secure CDN origins should be used to ensure traffic between ' +
                'the Azure CDN and backend service is encrypted.',
        pci: 'All card holder data must be transmitted over secure channels. ' +
                'Secure CDN origins should be used to ensure traffic between ' +
                'the Azure CDN and backend service is encrypted.'
    },

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.origins, (location, rcb) => {

            const origins = helpers.addSource(cache, source,
                ['origins', 'listByEndpoint', location]);

            if (!origins) return rcb();

            if (origins.err || !origins.data) {
                helpers.addResult(results, 3,
                    'Unable to query CDN Profile Endpoint Origins: ' + helpers.addError(origins), location);
                return rcb();
            }

            if (!origins.data.length) {
                helpers.addResult(results, 0, 'No existing CDN Profile Endpoint Origins', location);
                return rcb();
            }

            let isInsecureCustomOrigin = false;

            for (let res in origins.data) {
                let Origin = origins.data[res];
                if (Origin.httpsPort == undefined
                    && Origin.hostName.indexOf("blob.core.windows.net") == -1
                    && Origin.hostName.indexOf("cloudapp.net") == -1
                    && Origin.hostName.indexOf("azurewebsites.net") == -1) {

                    isInsecureCustomOrigin = true
                    helpers.addResult(results, 2,
                        `The Custom Origin has HTTPS disabled.`, location, Origin.hostName);
                }
            }

            if (isInsecureCustomOrigin != true) {
                helpers.addResult(results, 0,
                    'All custom origins have HTTPS enabled.', location);
            }
            rcb();
        }, function () {
            callback(null, results, source);
        });
    }
};
