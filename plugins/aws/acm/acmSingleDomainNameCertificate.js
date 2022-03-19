var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ACM Single Domain Name Certificates',
    category: 'ACM',
    domain: 'Identity and Access management',
    description: 'Ensure that ACM single domain name certificates are used instead of wildcard certificates within your AWS account.',
    more_info: 'ACM certificates are domain validated i.e. the subject field of an ACM certificate identifies a domain name and nothing more. ACM allows you to use an asterisk (*) in the domain name to create an ACM certificate containing a wildcard name that can protect several sites in the same domain.' + 
        'When you request a wildcard certificate, the asterisk (*) must be in the leftmost position of the domain name and can protect only one subdomain level.',
    link: 'https://docs.aws.amazon.com/acm/latest/userguide/acm-certificate.html',
    recommended_action: 'Configure ACM managed certificates to use single name domain instead of wildcards.',
    apis: ['ACM:listCertificates', 'ACM:describeCertificate'],

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

            // Loop through certificates
            listCertificates.data.forEach(function(cert){
                var describeCertificate = helpers.addSource(cache, source,
                    ['acm', 'describeCertificate', region, cert.CertificateArn]);

                if (!describeCertificate || describeCertificate.err || !describeCertificate.data) {
                    helpers.addResult(results, 3,
                        'Unable to describe ACM certificate: ' + helpers.addError(describeCertificate), region, 
                        cert.CertificateArn);
                    return;
                }  
                
                if (describeCertificate.data.Certificate &&
                    describeCertificate.data.Certificate.DomainName &&
                    describeCertificate.data.Certificate.DomainName.includes('*')) {
                    helpers.addResult(results, 2,
                        'Selected AWS ACM certificate is a wildcard certificate', region,
                        cert.CertificateArn);
                } else {
                    helpers.addResult(results, 0,
                        'Selected AWS ACM certificate is a single domain name certificate', region, 
                        cert.CertificateArn);
                } 
                
            });
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
