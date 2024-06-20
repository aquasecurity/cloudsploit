var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'DocumentDB Cluster Instance Certificate Rotation',
    category: 'DocumentDB',
    domain: 'Databases',
    severity: 'High',
    description: 'Ensure that DocumentDB cluster instance certificates are rotated.',
    more_info: 'Enabling the AWS DocumentDB cluster certificate rotation ensures that your cluster\'s TLS certificates are automatically rotated to maintain security and compliance standards. This feature helps in seamlessly updating certificates without downtime, ensuring continuous protection for data in transit within the DocumentDB cluster.',
    recommended_action: 'Modify DocumentDB cluster instance and rotate the old server certificate.',
    link: 'https://docs.aws.amazon.com/documentdb/latest/developerguide/ca_cert_rotation.html',
    apis: ['RDS:describeDBInstances'],
    settings: {
        docdb_certificate_rotation_limit: {
            name: 'Certificate Rotation Limit',
            description: 'Number of days before expiration date when certificate should be rotated',
            regex: '^[0-9]*$',
            default: '30',
        }
    },
    realtime_triggers: ['docdb:CreateDBInstance','docdb:DeleteDBInstance', 'docdb:ModifyDBInstance'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var docdb_certificate_rotation_limit = parseInt(settings.docdb_certificate_rotation_limit || this.settings.docdb_certificate_rotation_limit.default);

        async.each(regions.rds, function(region, rcb){
            var describeDBInstances = helpers.addSource(cache, source,
                ['rds', 'describeDBInstances', region]);

            if (!describeDBInstances) return rcb();

            if (describeDBInstances.err || !describeDBInstances.data) {
                helpers.addResult(results, 3,
                    `Unable to list DocumentDB cluster instances: ${helpers.addError(describeDBInstances)}`, region);
                return rcb();
            }

            if (!describeDBInstances.data.length) {
                helpers.addResult(results, 0,
                    'No DocumentDB cluster instances found', region);
                return rcb();
            }
            
            for (let instance of describeDBInstances.data) {
                if (!instance.DBInstanceArn) continue;

                if (!instance.Engine || instance.Engine.toLowerCase() != 'docdb') continue;
               
                let resource = instance.DBInstanceArn;
    
                if (instance.CertificateDetails && 
                    instance.CertificateDetails.ValidTill) {
                    var then = new Date(instance.CertificateDetails.ValidTill);
                    var difference = Math.round((new Date(then).getTime() - new Date().getTime())/(24*60*60*1000));

                    if (difference > docdb_certificate_rotation_limit) {
                        helpers.addResult(results, 0, `DocumentDB cluster instance does not need certificate rotation as it expires in ${difference} days ` +
                            `of ${docdb_certificate_rotation_limit} days limit`, region, resource);
                    } else {
                        helpers.addResult(results, 2, `DocumentDB cluster instance needs certificate rotation as it expires in ${difference} days ` +
                            `of ${docdb_certificate_rotation_limit} days limit`, region, resource);
                    } 
                }
                    
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
}; 