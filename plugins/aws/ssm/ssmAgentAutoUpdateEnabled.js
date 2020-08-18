var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SSM Agent Auto Update Enabled',
    category: 'SSM',
    description: 'Ensures the SSM agent is configured to automatically update to new versions',
    more_info: 'To ensure the latest version of the SSM agent is installed, it should be configured to consume automatic updates.',
    link: 'https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent-automatic-updates.html',
    recommended_action: 'Update the SSM agent configuration for all managed instances to use automatic updates.',
    apis: ['SSM:describeInstanceInformation'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ssm, function(region, rcb){
            var describeInstanceInformation = helpers.addSource(cache, source,
                ['ssm', 'describeInstanceInformation', region]);

            if (!describeInstanceInformation) return rcb();

            if (describeInstanceInformation.err || !describeInstanceInformation.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SSM instance information: ' + helpers.addError(describeInstanceInformation), region);
                return rcb();
            }
            console.log(describeInstanceInformation);
            
            //********************************
            //* 
            //* 
            //* ssm describe-instance-information -> instance id
            //* ssm list-association with instance id
            //* currently no instance id attribute is displayed in association
            //* look for a way to get association from instance id
            //* ALTERNATE: list-association will return all the associations and in Targets.instanceIds look for the instance id
            //* 
            //* 
            //* 
            //*********************************

            if(!describeInstanceInformation.data.length) {
                helpers.addResult(results, 2,
                    'No instance found in SSM instance information', region);
                return rcb();
            }

            describeInstanceInformation.data.forEach(function(instance){
                if (instance.IsLatestVersion) {
                    helpers.addResult(results, 0,
                        'SSM Agent auto update is enabled', region, instance.InstanceId);
                }
                else {
                    helpers.addResult(results, 2,
                        'SSM Agent auto update is disabled', region, instance.InstanceId);    
                }
            });
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
}