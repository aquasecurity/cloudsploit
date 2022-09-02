var async = require('async');
var helpers = require('../../../helpers/aws');
// const { athena, finspace, healthlake } = require('../../../helpers/aws/regions');

module.exports = {
    title: 'AWS Config Services In Use',
    category: 'ConfigService',
    domain: 'Management and Governance',
    severity: 'MEDIUM',
    description: 'Ensures that AWS ConfigService is in use that enables you to assess, and evaluate the configurations of your AWS resources.',
    more_info: 'AWS ConfigService is a fully managed service that provides you with a detailed inventory of your AWS resources and their current configurations. This service also records your configuration history and notifies you when your configurations change.',
    recommended_action: 'Enable the AWS Config Service settings for recorder checks to start recording.',
    link: 'https://docs.aws.amazon.com/config/latest/developerguide/how-does-config-work.html',
    apis: ['ConfigService:describeConfigurationRecorderStatus', 'ConfigService:getDiscoveredResourceCounts'],
    settings: {
        config_service_in_use: {
            name: 'Config Service In Use',
            description: 'Comma separated list of resource types that are is use i.e. iam,ec2',
            regex: '^.*$',
            default:''
        },
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            config_service_in_use:(settings.config_service_in_use || this.settings.config_service_in_use.default)
        };

        config.config_service_in_use = config.config_service_in_use.replace(/\s/g, '');

        if (!config.config_service_in_use.length) return callback(null, results, source);
        
        config.config_service_in_use = config.config_service_in_use.toLowerCase().split(',');

        const allServices = {
            'accessanalyzer': 'accessanalyzer',
            'appflow': 'af',
            'appmesh': 'am',
            'apprunner': 'ar',
            'athena': 'athena',
            'auditmanager': 'auditmanager',
            'apigateway': 'apigateway' ,
            'cloudfront': 'cfn',
            'cloudwatch': 'cw',
            'dynamodb': 'dynamodb',
            'documentdb': 'documentdb',
            'ec2':'ec2',
            'ecr': 'ecr',
            'ecs': 'ecs',
            'efs': 'efs',
            'eks': 'eks',
            'emr': 'emr',
            'elasticache': 'ec',
            'elastictranscoder': 'et',
            'eventbridge': 'eb',
            'finspace': 'finspace',
            'firehose': 'firehose',
            'forecast': 'forecast',
            'frauddetector': 'fd',
            'fsx': 'fsx',
            'glue': 'glue',
            'healthake': 'healthlake',
            'imagebuilder': 'ib',
            'kendra': 'kendra',
            'lex': 'lex',
            'location': 'location',
            'managedblockchain': 'mnb',
            'memorydb': 'memorydb',
            'mq': 'mq',
            'msk': 'msk',
            'mwaa': 'mwaa',
            'neptune': 'neptune', 
            'guardduty': 'guardduty',
            'elasticsearch': 'es',
            'opensearch': 'opensearch',
            'organizations': 'organizations',
            'proton': 'proton',
            'route53': 'route53',
            'qldb': 'qldb',
            'kinesis': 'kinesis',
            'redshift': 'redshift',
            'rds': 'rds',
            'sagemaker': 'sagemaker',
            's3': 's3',
            'autoscaling': 'autoscaling',
            'backup': 'backup',
            'acm': 'acm',
            'cloudformation': 'cfn',
            'cloudwatch': 'cw',
            'cloudwatchlogs': 'cwl',
            'codeartifact': 'ca',
            'codestar': 'cs',
            'comprehend': 'comprehend',
            'computeoptimizer': 'co',
            'dms': 'dms',
            'cloudtrail': 'ct',
            'codebuild': 'cb',
            'codedeploy': 'cd',
            'codepipeline': 'cp',
            'config': 'config',
            'connect': 'connect',
            'devopsguru': 'devopsguru',
            'elasticbeanstalk': 'ebs',
            'iam': 'iam',
            'kms':  'kms',
            'lambda': 'lambda',
            'networkfirewall': 'networkfirewall',
            'secretsmanager': 'secretsmanager',
            'servicecatalog': 'servicecatalog',
            'shield': 'shield',
            'sns': 'sns',
            'sqs': 'sqs',
            'stepfunctions': 'stepfunctions',
            'ssm': 'ssm',
            'waf': 'waf',
            'timestreamwrite':'tsw',
            'transfer': 'transfer',
            'translate': 'translate',
            'workspaces': 'workspaces', 
            'wafv2': 'wafv2',
            'xray': 'xray',
            'elasticloadbalancing': 'elb',
            'elasticloadbalancingv2': 'elbv2'
        };

        async.each(regions.configservice, function(region, rcb){        
            var configRecorderStatus = helpers.addSource(cache, source,
                ['configservice', 'describeConfigurationRecorderStatus', region]);

            if (!configRecorderStatus) {
                return rcb();
            }

            if (configRecorderStatus.err || !configRecorderStatus.data) {
                helpers.addResult(results, 3,
                    'Unable to query config service: ' + helpers.addError(configRecorderStatus), region);
                return rcb();
            }

            if (!configRecorderStatus.data.length) {
                helpers.addResult(results, 2,
                    'Config service is not enabled', region);
                return rcb();
            }

            if (!configRecorderStatus.data[0].recording) {
                helpers.addResult(results, 2,
                    'Config service is not recording', region);
                return rcb();
            }

            if (!configRecorderStatus.data[0].lastStatus ||
                (configRecorderStatus.data[0].lastStatus.toUpperCase() !== 'SUCCESS' &&
                configRecorderStatus.data[0].lastStatus.toUpperCase() !== 'PENDING')) {
                helpers.addResult(results, 2,
                    'Config Service is configured, and recording, but not delivering properly', region);
                return rcb();
            }

            var discoveredResources = helpers.addSource(cache, source,
                ['configservice', 'getDiscoveredResourceCounts', region]);

            if (discoveredResources.err || !discoveredResources.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Discovered Resources: ' + helpers.addError(discoveredResources));
                return rcb();
            }

            let usedServices = [];
            for (let resource of discoveredResources.data){
                if (resource.resourceType){
                    let newResource = resource.resourceType.split('::');
                    if (newResource[1].length > 1 && !usedServices.includes(newResource[1].toLowerCase())) usedServices.push(newResource[1].toLowerCase())
                };
            }

            let array = []
            for (let value of usedServices){
                if (allServices[value]) array.push(allServices[value]);
            };

            array = array.filter(service => !config.config_service_in_use.includes(service));
            if (array.length){
                helpers.addResult(results, 2,
                    'These services are being used which are not allowed: ' + array.join(','), region);
            } else {
                helpers.addResult(results, 0,
                    'Allowed services are being used', region);
            }
            rcb();  
        }, function(){
            callback(null, results, source);
        });
    }
};

