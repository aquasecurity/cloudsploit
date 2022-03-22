var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Backup Resource Protection',
    category: 'Backup',
    domain: 'Storage',
    severity: 'Low',
    description: 'Ensure that protected resource types feature is enabled and configured for Amazon Backup service within your AWS cloud account.',
    more_info: 'Amazon Backup Protected Resource Types feature allows you to choose which resource types are protected by backup plans on per-region basis.',
    recommended_action: 'Enable protected resource type feature in order to meet compliance requirements.',
    link: 'https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html',
    apis: ['Backup:describeRegionSettings'],
    settings: {
        backup_resource_type: {
            name: 'Protected Amazon Backup Resource Types',
            description: 'If set, Backup protected resource types should have a retention settings of boolean true or false.',
            regex: '^.*$',
            default:'rds, efs, aurora, dynamodb, storage gateway, ec2, ebs, virtual machine'
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            backup_resource_type:(settings.backup_resource_type || this.settings.backup_resource_type.default)
        };
        config.backup_resource_type = config.backup_resource_type.replace(/\s/g, '');
        config.backup_resource_type = config.backup_resource_type.split(',');
        config.backup_resource_type = config.backup_resource_type.map(v => v.toLowerCase());

        if (!config.backup_resource_type.length) return callback(null, results, source);

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

            let objt = describeRegionSettings.data;
            const lowercaseKeys = obj =>
                Object.keys(obj).reduce((acc, key) => {
                    acc[key.toLowerCase()] = obj[key];
                    return acc;
                }, {});
            let myObjLower = lowercaseKeys(objt);   

            let allPassed = true;
            config.backup_resource_type.forEach(element => {
                if (myObjLower[element] === false) {
                    allPassed = false;
                    return;
                }   
            });
                
            if (allPassed) {
                helpers.addResult(results, 0,
                    'Backup configuration for protected resource types is compliant', region);
            } else {
                helpers.addResult(results, 2,
                    'Backup configuration for protected resource types is not compliant', region);
            } 

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
