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
        cloudfront_whitelisted_regions: {
            name: 'CloudFront WhiteListed Regions',
            description: 'A comma-delimited list of CloudFront regions which should be allowed, for example AR=Argentine, EG=Egypt etc ',
            regex: '[a-zA-Z0-9-,]',
            default: 'AF,EG'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);

        var config = {
            cloudfront_whitelisted_regions: settings.cloudfront_whitelisted_regions || this.settings.cloudfront_whitelisted_regions.default, 
        };

        if (!config.cloudfront_whitelisted_regions.length) return callback();
        config.cloudfront_whitelisted_regions = config.cloudfront_whitelisted_regions.split(',');
        config.cloudfront_whitelisted_regions = JSON.stringify(config.cloudfront_whitelisted_regions);
        
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
                && distribution.Restrictions.GeoRestriction.RestrictionType.toLowerCase() === 'whitelist'){
                let item = distribution.Restrictions.GeoRestriction.Items;
                let whitelistItems = item.filter(element => config.cloudfront_whitelisted_regions.includes(element));
                if (whitelistItems.length) {
                    helpers.addResult(results, 0,
                        `CloudFront distribution has ${whitelistItems} available for its content distribution.`, 'global', distribution.ARN);
                } else {
                    helpers.addResult(results, 2,
                        'CloudFront distribution does not have region available for its content distribution', 'global', distribution.ARN);
                }
            
            } else if (distribution.Restrictions && distribution.Restrictions.GeoRestriction 
                && distribution.Restrictions.GeoRestriction.RestrictionType 
                && distribution.Restrictions.GeoRestriction.RestrictionType.toLowerCase() === 'blacklist'){
                let items = distribution.Restrictions.GeoRestriction.Items;
                let blacklistItems = items.filter(element => config.cloudfront_whitelisted_regions.includes(element));
                if (blacklistItems.length) {
                    helpers.addResult(results, 2,
                        `CloudFront distribution has ${blacklistItems} region blacklisted for its content distribution.`, 'global', distribution.ARN);
                } else {
                    helpers.addResult(results, 0,
                        'CloudFront distribution does not have Blacklisted regions for its content distribution', 'global', distribution.ARN);
                }    
            }

            if (distribution.Restrictions && distribution.Restrictions.GeoRestriction 
                && distribution.Restrictions.GeoRestriction.RestrictionType 
                && distribution.Restrictions.GeoRestriction.RestrictionType.toLowerCase() != 'none') {
                helpers.addResult(results, 0,
                    'Geo restriction feature is enabled within CloudFront distribution.', 'global', distribution.ARN);
            } else {
                helpers.addResult(results, 2,
                    'Geo restriction feature is not enabled within CloudFront distribution.', 'global', distribution.ARN);
            }
            
        });

        return callback(null, results, source);
    }
};