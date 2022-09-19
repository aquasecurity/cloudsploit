var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFront Geo Restriction',
    category: 'CloudFront',
    domain: 'Content Delivery',
    description: 'Ensure that geo-restriction feature is enabled for your CloudFront distribution to allow or block location-based access.',
    more_info: ' AWS CloudFront geo restriction feature can be used to assist in mitigation of Distributed Denial of Service (DDoS) attacks. ' +
               'Also you have the ability to block IP addresses based on Geo IP from reaching your distribution and your web application content delivered by the distribution.',
    link: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/georestrictions.html',
    recommended_action: 'Enable CloudFront geo restriction to whitelist or block location-based access.',
    apis: ['CloudFront:listDistributions'],
    settings: {
        cloudfront_whitelisted_geo_locations: {
            name: 'CloudFront WhiteListed Geographic Locations',
            description: 'A comma-delimited list of shorthands for geographic locations which should be allowed within CloudFront distribution geographic restriction settings, i.e. AR=Argentine, EG=Egypt',
            regex: '[a-zA-Z0-9-,]',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);

        var config = {
            cloudfront_whitelisted_geo_locations: settings.cloudfront_whitelisted_geo_locations || this.settings.cloudfront_whitelisted_geo_locations.default, 
        };

        config.cloudfront_whitelisted_geo_locations = config.cloudfront_whitelisted_geo_locations.toUpperCase().replace(/\s/g, '');
        
        var listDistributions = helpers.addSource(cache, source,
            ['cloudfront', 'listDistributions', region]);

        if (!listDistributions) return callback(null, results, source);

        if (listDistributions.err || !listDistributions.data) {
            helpers.addResult(results, 3,
                'Unable to query for CloudFront distributions: ' + helpers.addError(listDistributions), 'global');
            return callback(null, results, source);
        }

        if (!listDistributions.data.length) {
            helpers.addResult(results, 0, 'No CloudFront distributions found', 'global');
            return callback(null, results, source);
        }
   
        listDistributions.data.forEach(distribution => {
            if (distribution.Restrictions && distribution.Restrictions.GeoRestriction 
                && distribution.Restrictions.GeoRestriction.RestrictionType 
                && distribution.Restrictions.GeoRestriction.RestrictionType.toLowerCase() === 'none') {
                helpers.addResult(results, 2,
                    'Geo restriction feature is not enabled within CloudFront distribution', 'global', distribution.ARN);
            } else if (config.cloudfront_whitelisted_geo_locations.length) {
                config.cloudfront_whitelisted_geo_locations = config.cloudfront_whitelisted_geo_locations.split(',');
                if (distribution.Restrictions.GeoRestriction.RestrictionType.toLowerCase() === 'whitelist') {
                    let items = distribution.Restrictions.GeoRestriction.Items;
                    let missedLocations = config.cloudfront_whitelisted_geo_locations.filter(location => !items.includes(location));
                    if (missedLocations.length) {
                        helpers.addResult(results, 2,
                            `CloudFront distribution does not have these locations whitelisted: ${missedLocations.join(' ,')}`,
                            'global', distribution.ARN);
                    } else {
                        helpers.addResult(results, 0,
                            'CloudFront distribution is whitelisting required geographic locations',
                            'global', distribution.ARN);
                    }
                } else if (distribution.Restrictions.GeoRestriction.RestrictionType.toLowerCase() === 'blacklist') {
                    let items = distribution.Restrictions.GeoRestriction.Items;
                    let blockedLocations = config.cloudfront_whitelisted_geo_locations.filter(location => items.includes(location));

                    if (blockedLocations.length) {
                        helpers.addResult(results, 2,
                            `CloudFront distribution has these locations blacklisted: ${blockedLocations.join(' ,')}`,
                            'global', distribution.ARN);
                    } else {
                        helpers.addResult(results, 0,
                            'CloudFront distribution is whitelisting required geographic locations',
                            'global', distribution.ARN);
                    }
                } else {
                    helpers.addResult(results, 2,
                        'Geo restriction feature is not enabled within CloudFront distribution', 'global', distribution.ARN);
                }
            } else {
                helpers.addResult(results, 0,
                    'Geo restriction feature is enabled within CloudFront distribution', 'global', distribution.ARN);
            }            
        });

        return callback(null, results, source);
    }
};