var async = require('async');
var helpers = require('../../helpers');

module.exports = {
    title: 'ACM certificate validation',
    category: 'ACM',
    description: 'ACM certificates should be configured to use DNS validation.',
    more_info: 'With DNS validation ACM will automatically renew certificates before they expire, as long as the DNS CNAME record is in place.',
    link: 'https://aws.amazon.com/blogs/security/easier-certificate-validation-using-dns-with-aws-certificate-manager/',
    recommended_action: 'Configure ACM managed certificates to use DNS validation.',
    apis: ['ACM:listCertificates', 'ACM:describeCertificate'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        async.each(helpers.regions.acm, function(region, rcb){
            var describeCerts = helpers.addSource(cache, source,
                ['acm', 'listCertificates', region]);

            if (!describeCerts) return rcb();

            if (describeCerts.err || !describeCerts.data) {
                helpers.addResult(results, 3,
                    'Unable to list ACM certificates: ' + helpers.addError(describeCerts), region);
                return rcb();
            }

            if (!describeCerts.data.length) {
                helpers.addResult(results, 0, 'No ACM certificates found', region);
                return rcb();
            }

            // Loop through certificates
            describeCerts.data.forEach(function(cert){
		var certInfo = helpers.addSource(cache, source, ['acm', 'describeCertificate', region, cert.CertificateArn]);
		certInfo.data.Certificate.DomainValidationOptions.forEach(function(domain) {
			if(domain.ValidationStatus != 'SUCCESS') {
				helpers.addResult(results, 2, domain.DomainName + ' has failed ' + domain.ValidationMethod + ' validation.', region, cert.CertificateArn);
			} else if(domain.ValidationMethod != 'DNS') {
				helpers.addResult(results, 1, domain.DomainName + ' is using ' + domain.ValidationMethod + ' validation.', region, cert.CertificateArn);
			} else {
				helpers.addResult(results, 0, domain.DomainName + ' is using ' + domain.ValidationMethod + ' validation.', region, cert.CertificateArn);
			}
		});
            });
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
