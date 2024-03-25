var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Amazon Comprehend Flywheel In VPC',
    category: 'AI & ML',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensure that an Amazon Comprehend Flywheel is configured with a VPC.',
    more_info: 'When the Comprehend flywheel is configured within a VPC, it establishes a secure environment that prevents unauthorized internet access to your data stored in job containers, minimizing the risk of data breaches and ensuring compliance with security standards.',
    recommended_action: 'Update the Amazon Comprehend Flywheel and configure VPC',
    link: 'https://docs.aws.amazon.com/comprehend/latest/dg/usingVPC.html',
    apis: ['Comprehend:listFlywheels', 'Comprehend:describeFlywheel'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.comprehend, function(region, rcb){
            var listFlywheels = helpers.addSource(cache, source,
                ['comprehend', 'listFlywheels', region]);

            if (!listFlywheels) return rcb();

            if (listFlywheels.err || !listFlywheels.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Comprehend flywheel list: ${helpers.addError(listFlywheels)}`, region);
                return rcb();
            }

            if (!listFlywheels.data.length) {
                helpers.addResult(results, 0, 'No Comprehend flywheel found', region);
                return rcb();
            }

            for (let flywheel of listFlywheels.data){
              
                let resource = flywheel.FlywheelArn;

                let describeFlywheel = helpers.addSource(cache, source,
                    ['comprehend', 'describeFlywheel', region, flywheel.FlywheelArn]);

                if (!describeFlywheel || describeFlywheel.err || !describeFlywheel.data || !describeFlywheel.data.FlywheelProperties) {
                    helpers.addResult(results, 3, `Unable to describe Comprehend flywheel : ${helpers.addError(describeFlywheel)}`, region, resource);
                    continue;
                }

                if (describeFlywheel.data.FlywheelProperties.DataSecurityConfig &&  describeFlywheel.data.FlywheelProperties.DataSecurityConfig.VpcConfig) {
                    helpers.addResult(results, 0,
                        'Comprehend flywheel is configured within a VPC', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Comprehend flywheel is not configured within a VPC', region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};