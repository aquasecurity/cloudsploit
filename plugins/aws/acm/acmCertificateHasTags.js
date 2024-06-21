var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ACM Certificate Has Tags',
    category: 'ACM',
    domain: 'Identity and Access Management',
    severity: 'Low',
    description: 'Ensure that ACM Certificates have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://docs.aws.amazon.com/acm/latest/userguide/tags.html',
    recommended_action: 'Modify ACM certificate and add tags.',
    apis: ['ACM:listCertificates', 'ResourceGroupsTaggingAPI:getResources'],
    realtime_triggers: ['acm:RequestCertificate','acm:ImportCertificate','acm:DeleteCertificate','acm:AddTagsToCertificate', 'acm:RemoveTagsFromCertificate'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.acm, function(region, rcb){
            var listCertificates = helpers.addSource(cache, source,
                ['acm', 'listCertificates', region]);

            if (!listCertificates) return rcb();

            if (listCertificates.err || !listCertificates.data) {
                helpers.addResult(results, 3,
                    'Unable to list ACM certificates: ' + helpers.addError(listCertificates), region);
                return rcb();
            }

            if (!listCertificates.data.length) {
                helpers.addResult(results, 0, 'No ACM certificates found', region);
                return rcb();
            }
            const ARNList= [];
            for (var cert of listCertificates.data){
                if (!cert.CertificateArn) continue;
                
                ARNList.push(cert.CertificateArn);
            }
            helpers.checkTags(cache, 'ACM certificate', ARNList, region, results, settings);
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
