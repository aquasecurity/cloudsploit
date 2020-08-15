var async = require('async');
const forge = require('node-forge');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Certificate Minimum Size',
    category: 'IAM',
    description: 'Ensures TLS certificates uploaded to IAM are at least 2048 bytes.',
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
                'Unable to find any server certificates ' + helpers.addError(listServerCertificates), region);
            return callback(null, results, source);
        }

        if (listServerCertificates.data.length == 0) {
            helpers.addResult(results, 2, 'No server certificate found', region);
            return callback(null, results, source);
        }

        async.each(listServerCertificates.data, function(certificate, cb){
            var serverCertificate = helpers.addSource(cache, source,
                ['iam', 'getServerCertificate', region, certificate.ServerCertificateName]);
            var resource = certificate.ServerCertificateName;

            if (!serverCertificate || serverCertificate.err || !serverCertificate.data) {
                helpers.addResult(results, 3,
                    'Unable to get server certificate ' + helpers.addError(listServerCertificates), region);
                return cb();
            }

            if (serverCertificate.data.length == 0) {
                helpers.addResult(results, 2, 'No server certificate found', region);
                return cb();
            }

            if(!serverCertificate.data.ServerCertificate  || !serverCertificate.data.ServerCertificate.CertificateBody) {
                helpers.addResult(results, 3,
                    'Unable to get IAM server certificate body ' + helpers.addError(listServerCertificates), region);
                return cb();
            }

            const certificatePem = forge.pki.certificateFromPem(serverCertificate.data.ServerCertificate.CertificateBody);

            const certificateBitLength = certificatePem.publicKey.n.bitLength();
            if (certificateBitLength >= 2048) {
                helpers.addResult(results, 0,
                    'IAM Certificate is security complient with 2048 bit key length', region, resource);
            }
            else {
                helpers.addResult(results, 1,
                    'IAM Certificate should have atleast 2048 bit key length', region, resource);
            }
            return cb();
        }, function(){
            callback(null, results, source);
        });
       
    }
};