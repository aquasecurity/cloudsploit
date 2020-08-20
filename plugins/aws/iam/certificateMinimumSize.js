var async = require('async');
const forge = require('node-forge');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Certificate Minimum Size',
    category: 'IAM',
    description: 'Ensures TLS certificates uploaded to IAM are at least 2048 bytes',
    more_info: 'IAM certificates should be at least 2048 bytes rather than 1024 bytes for improved certificate security.',
    link: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html',
    recommended_action: 'Re-create and re-upload the certificate to ensure the correct certificate size.',
    apis: ['IAM:listServerCertificates', 'IAM:getServerCertificate'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var listServerCertificates = helpers.addSource(cache, source,
            ['iam', 'listServerCertificates', region]);

        if (!listServerCertificates) return callback(null, results, source);

        if (listServerCertificates.err || !listServerCertificates.data) {
            helpers.addResult(results, 3,
                'Unable to query for server certificates: ' + helpers.addError(listServerCertificates), region);
            return callback(null, results, source);
        }

        if (!listServerCertificates.data.length) {
            helpers.addResult(results, 0, 'No server certificate found');
            return callback(null, results, source);
        }

        async.each(listServerCertificates.data, function(certificate, cb){
            var resource = certificate.Arn;
            var serverCertificate = helpers.addSource(cache, source,
                ['iam', 'getServerCertificate', region, certificate.ServerCertificateName]);

            if (!serverCertificate ||
                serverCertificate.err ||
                !serverCertificate.data ||
                !serverCertificate.data.ServerCertificate) {
                helpers.addResult(results, 3,
                    'Unable to query server certificate for: ' + certificate.ServerCertificateName + ': ' + helpers.addError(serverCertificate),
                    'global', resource);
                return cb();
            }

            if (!serverCertificate.data.ServerCertificate.CertificateBody) {
                helpers.addResult(results, 3,
                    'Unable to get certificate body for: ' + certificate.ServerCertificateName, 'global', resource);
                return cb();
            }

            const certificatePem = forge.pki.certificateFromPem(serverCertificate.data.ServerCertificate.CertificateBody);
            const certificateBitLength = certificatePem.publicKey.n.bitLength();

            if (certificateBitLength >= 2048) {
                helpers.addResult(results, 0,
                    'IAM Certificate ' + certificate.ServerCertificateName + ' is security complient with 2048 bit key length', 'global', resource);
            } else {
                helpers.addResult(results, 2,
                    'IAM Certificate ' + certificate.ServerCertificateName + ' is not security complient with 2048 bit key length', 'global', resource);
            }
            
            cb();
        }, function(){
            callback(null, results, source);
        });
    }
};