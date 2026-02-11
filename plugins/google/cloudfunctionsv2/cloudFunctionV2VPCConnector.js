var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Cloud Function V2 Serverless VPC Access',
    category: 'Cloud Functions',
    domain: 'Serverless',
    severity: 'High',
    description: 'Ensure that Cloud Functions V2 are allowed to access only VPC resources.',
    more_info: 'Cloud Functions V2 may require to connect directly to Compute Engine VM instances, Memorystore instances, Cloud SQL instances, and any other resources. It is a best practice to send requests to these resources using an internal IP address by connecting to VPC network using "Serverless VPC Access" configuration.',
    link: 'https://cloud.google.com/functions/docs/networking/connecting-vpc#create-connector',
    recommended_action: 'Ensure all Cloud Functions V2 are using serverless VPC connectors.',
    apis: ['functionsv2:list'],
    realtime_triggers: ['functions.CloudFunctionsService.UpdateFunction', 'functions.CloudFunctionsService.CreateFunction', 'functions.CloudFunctionsService.DeleteFunction'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();
        
        async.each(regions.functions, (region, rcb) => {
            var functions = helpers.addSource(cache, source,
                ['functionsv2', 'list', region]);

            if (!functions) return rcb();

            if (functions.err || !functions.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Google Cloud functions: ' + helpers.addError(functions), region, null, null, functions.err);
                return rcb();
            }

            if (!functions.data.length) {
                helpers.addResult(results, 0, 'No Google Cloud functions found', region);
                return rcb();
            }

            functions.data.forEach(func => {
                if (!func.name) return;

                if (!func.buildConfig || !func.buildConfig.functionTarget) return;

                let vpcAccess = func.template && func.template.vpcAccess ? func.template.vpcAccess : null;
                let egress = vpcAccess ? vpcAccess.egress : null;

                if (vpcAccess && (vpcAccess.connector || (vpcAccess.networkInterfaces && vpcAccess.networkInterfaces.length))) {
                    if (egress && egress.toUpperCase() === 'ALL_TRAFFIC') {
                        helpers.addResult(results, 0,
                            'Cloud Function is using a VPC Connector to route all traffic', region, func.name);
                    } else {
                        helpers.addResult(results, 2,
                            'Cloud Function is using a VPC Connector for requests to private IPs only', region, func.name);
                    }
                } else {
                    helpers.addResult(results, 2,
                        'Cloud Function is not configured with Serverless VPC Access', region, func.name);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

