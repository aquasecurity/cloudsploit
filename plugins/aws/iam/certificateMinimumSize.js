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
        // console.log(listServerCertificates);
        // console.log("data received");
        if (!listServerCertificates) return callback(null, results, source);

        if (listServerCertificates.err || !listServerCertificates.data) {
            helpers.addResult(results, 3,
                'Unable to find any server certificates: ' + helpers.addError(listServerCertificates));
            return callback(null, results, source);
        }

        if (listServerCertificates.data.length == 0) {
            helpers.addResult(results, 0, 'No server certificate found');
            return callback(null, results, source);
        }

        listServerCertificates.data.forEach(function(certificate){
            console.log(certificate.ServerCertificateName);
            var serverCertificate = helpers.addSource(cache, source,
                ['iam', 'getServerCertificate', 'us-east-1', certificate.ServerCertificateName]);
             console.log('response');
             console.log(serverCertificate);
        });
        CertificateBody =  "-----BEGIN CERTIFICATE-----\nMIIC6jCCAdKgAwIBAgIJAMCqFZnVrZiRMA0GCSqGSIb3DQEBBQUAMCExHzAdBgNV\nBAMTFnd3dy5zc2xjZXJ0aWZpY2F0ZS5jb20wHhcNMjAwODEyMjAxOTUxWhcNMzAw\nODEwMjAxOTUxWjAhMR8wHQYDVQQDExZ3d3cuc3NsY2VydGlmaWNhdGUuY29tMIIB\nIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoiFyqwi2NvNb1Ky9RmEx4JQP\nXSvmWYLc9DD+g6QR4wvEdq4U/X3D8jVw82tbMKOZYHVtlcPzl79LnuLo/rAqjyTA\nOJLR37c+BK7xghpb8Aozt1VX9si9exBSmndDx7r5hMIA4PInXz3vCdtQiEJk1G3D\nXOjelHfkiFwnF7166Bxv4n2IsnqaV3bdIPEWOc5+aqROtd3xonzzVS6jEKW7S9bD\n+3QCILMimcbUu5MkYetVse1VBe4ZTRItmSTY3j6HXeHn58GPqoteiCClK7Xzvrkg\nFFZ1deGzQDf6ZNJYUba93m2V3Gn4kjyBimbAHOE+04OXPEkznzF0mQHnbleFewID\nAQABoyUwIzAhBgNVHREEGjAYghZ3d3cuc3NsY2VydGlmaWNhdGUuY29tMA0GCSqG\nSIb3DQEBBQUAA4IBAQBZi/MO23r5xjYsiM2jM8lDHngoS1EwP9RqIYx7cXdwIHR/\nSKEllu2/VLIWbq6WI0cg5No2QWqbW3KzmIinARHIjgcd+WI7mod68i1EnZHsLU75\n1lEfVdFqhYVmT3WqXNWeyTstedhGUWJocRM41nUbmR+E+XUA40L0XSXoReBXCdQ9\nc3ia3jQpyq/qt86zreUeaIllCgcIcAUR0XKz+lb0w6/mPNgJgLuBllbnuRDDqvs/\nVfskYw+lmEFSP7pL7MaYTYZomlsAya4jc8Uw5AmMPRRV0K6TOBPVGvgXWBPX2v05\nOmbDpF3aoYW7Z05AXcu7CCezAzLFYInJSqt6ruWH\n-----END CERTIFICATE-----"
        const certificate = forge.pki.certificateFromPem(CertificateBody);
        console.log(certificate.publicKey.n.bitLength());
       
    }
};