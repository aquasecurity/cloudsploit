var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Backup Resource Protection',
    category: 'Backup',
    domain: 'Storage',
    severity: 'LOW',
    description: 'Ensure that protected resource types feature is enabled and configured for Amazon Backup service within.',
    more_info: 'Amazon Backup protected resource types feature allows you to choose which resource types are protected by backup plans on per-region basis.',
    recommended_action: 'Enable protected resource type feature in order to meet compliance requirements.',
    link: 'https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html',
    apis: ['Backup:describeRegionSettings'],
    settings: {
        backup_resource_type: {
            name: 'Protected Amazon Backup Resource Types',
            description: 'Comma separated list of resource types that should be backup protected i.e. rds,efs',
            regex: '^.*$',
            default:''
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            backup_resource_type:(settings.backup_resource_type || this.settings.backup_resource_type.default)
        };

        config.backup_resource_type = config.backup_resource_type.replace(/\s/g, '');

        if (!config.backup_resource_type.length) return callback(null, results, source);

        config.backup_resource_type = config.backup_resource_type.toLowerCase().split(',');

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.backup, function(region, rcb){
            var describeRegionSettings = helpers.addSource(cache, source, 
                ['backup', 'describeRegionSettings', region]);
             
            if (!describeRegionSettings || describeRegionSettings.err ||
                !describeRegionSettings.data) {
                helpers.addResult(results, 3, `Unable to query for Backup resource type opt in preference: ${helpers.addError(describeRegionSettings)}`, region);
                return rcb();
            }

            if (!describeRegionSettings.data) {
                helpers.addResult(results, 0, 'No Backup region settings found', region);
                return rcb();
            }

            let loweredResourceTypes = Object.keys(describeRegionSettings.data).reduce((acc, key) => {
                acc[key.toLowerCase().replace(/\s/g, '')] = describeRegionSettings.data[key];
                return acc;
            }, {});
   
        
            let missingResourceTypes = [];
            config.backup_resource_type.forEach(element => {
                if (!loweredResourceTypes[element]) {
                    missingResourceTypes.push(element);
                }
            });

            if (!missingResourceTypes.length) {
                helpers.addResult(results, 0,
                    'All desired resource types are protected by Backup service', region);
            } else {
                helpers.addResult(results, 2,
                    'These desired resource types are not protected by Backup service: ' + missingResourceTypes.join(', '), region);
            } 

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
