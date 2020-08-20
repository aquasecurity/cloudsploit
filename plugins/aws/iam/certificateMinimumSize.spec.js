var expect = require('chai').expect;
const certificateMinimumSize = require('./certificateMinimumSize');

const listCertificates =  [
    {
        Path: '/',
        ServerCertificateName: 'ExampleCertificate',
        ServerCertificateId: 'ASCAYE32SRU5Z4FTTGYXD',
        Arn: 'arn:aws:iam::560213429563:server-certificate/ExampleCertificate',
        UploadDate: '2020-08-13T11:37:27.000Z',
        Expiration: '2030-08-10T20:19:51.000Z'
    }
];

const certificates = [
    { // Valid Server Certificate with 2048 bit length for getServerCertificate response
        ResponseMetadata: { RequestId: '1fc0aab6-e57c-4f05-9327-007419203c88' },
        ServerCertificate: {
            ServerCertificateMetadata: {
                Path: '/',
                ServerCertificateName: 'ExampleCertificate',
                ServerCertificateId: 'ASCAYE32SRU5Z4FTTGYXD',
                Arn: 'arn:aws:iam::560213429563:server-certificate/ExampleCertificate',
                UploadDate: '2020-08-13T11:37:27.000Z',
                Expiration: '2030-08-10T20:19:51.000Z'
            },
            CertificateBody: '-----BEGIN CERTIFICATE-----\n' +
                'MIIC6jCCAdKgAwIBAgIJAMCqFZnVrZiRMA0GCSqGSIb3DQEBBQUAMCExHzAdBgNV\n' +
                'BAMTFnd3dy5zc2xjZXJ0aWZpY2F0ZS5jb20wHhcNMjAwODEyMjAxOTUxWhcNMzAw\n' +
                'ODEwMjAxOTUxWjAhMR8wHQYDVQQDExZ3d3cuc3NsY2VydGlmaWNhdGUuY29tMIIB\n' +
                'IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoiFyqwi2NvNb1Ky9RmEx4JQP\n' +
                'XSvmWYLc9DD+g6QR4wvEdq4U/X3D8jVw82tbMKOZYHVtlcPzl79LnuLo/rAqjyTA\n' +
                'OJLR37c+BK7xghpb8Aozt1VX9si9exBSmndDx7r5hMIA4PInXz3vCdtQiEJk1G3D\n' +
                'XOjelHfkiFwnF7166Bxv4n2IsnqaV3bdIPEWOc5+aqROtd3xonzzVS6jEKW7S9bD\n' +
                '+3QCILMimcbUu5MkYetVse1VBe4ZTRItmSTY3j6HXeHn58GPqoteiCClK7Xzvrkg\n' +
                'FFZ1deGzQDf6ZNJYUba93m2V3Gn4kjyBimbAHOE+04OXPEkznzF0mQHnbleFewID\n' +
                'AQABoyUwIzAhBgNVHREEGjAYghZ3d3cuc3NsY2VydGlmaWNhdGUuY29tMA0GCSqG\n' +
                'SIb3DQEBBQUAA4IBAQBZi/MO23r5xjYsiM2jM8lDHngoS1EwP9RqIYx7cXdwIHR/\n' +
                'SKEllu2/VLIWbq6WI0cg5No2QWqbW3KzmIinARHIjgcd+WI7mod68i1EnZHsLU75\n' +
                '1lEfVdFqhYVmT3WqXNWeyTstedhGUWJocRM41nUbmR+E+XUA40L0XSXoReBXCdQ9\n' +
                'c3ia3jQpyq/qt86zreUeaIllCgcIcAUR0XKz+lb0w6/mPNgJgLuBllbnuRDDqvs/\n' +
                'VfskYw+lmEFSP7pL7MaYTYZomlsAya4jc8Uw5AmMPRRV0K6TOBPVGvgXWBPX2v05\n' +
                'OmbDpF3aoYW7Z05AXcu7CCezAzLFYInJSqt6ruWH\n' +
                '-----END CERTIFICATE-----'
        }
    },
    {// Valid Server Certificate with 1024 bit length for getServerCertificate response
        ResponseMetadata: { RequestId: '1fc0aab6-e57c-4f05-9327-007419203c88' },
        ServerCertificate: {
            ServerCertificateMetadata: {
                Path: '/',
                ServerCertificateName: 'ExampleCertificate',
                ServerCertificateId: 'ASCAYE32SRU5Z4FTTGYXD',
                Arn: 'arn:aws:iam::560213429563:server-certificate/ExampleCertificate',
                UploadDate: '2020-08-13T11:37:27.000Z',
                Expiration: '2030-08-10T20:19:51.000Z'
            },
            CertificateBody:    '-----BEGIN CERTIFICATE-----\n' +
                'MIICCDCCAXGgAwIBAgIUWb+eZfe6bQpzESrh2yKAiJqrPUswDQYJKoZIhvcNAQEL\n' +
                'BQAwADAeFw0yMDA4MTUxNDE2MjNaFw0zMDA4MTMxNDE2MjNaMAAwgZ8wDQYJKoZI\n' +
                'hvcNAQEBBQADgY0AMIGJAoGBAMAFcnpC632EkANCt+uH9m3G9ZLLNU5f5AG39l00\n' +
                'wPQMII7UnQrUS2qQhpQfgpxY0SH02hIe4iDzTJwQ+iwk5M0SOKQhlwoJykYPPctF\n' +
                '8RRvjvD0w2wONZUQ2cFZO3Fexoc+dNRC35uTzwFqRfvcOG9rxRyiNtfyAhIPxLRQ\n' +
                'ehNtAgMBAAGjfzB9MB0GA1UdDgQWBBSvDp68Y22SIbRltkCPAUo8oGQpsjAfBgNV\n' +
                'HSMEGDAWgBSvDp68Y22SIbRltkCPAUo8oGQpsjAOBgNVHQ8BAf8EBAMCBaAwHQYD\n' +
                'VR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwDQYJKoZI\n' +
                'hvcNAQELBQADgYEAOX0OF6+uDngJjqocyhVL7G1c+35nkdQGonoRaCBCUeefNrvP\n' +
                'JDtv8obMunuVKgxTFdgmoKOAvRfRWX+Sao3+DWq81f5w9InoHoYcijJY8LxYU0ig\n' +
                '2BGpVoARHE6oeaqco5Sn1X1pTKUsG/Z0LxHZkt1fBrf/f9btHfDzq6i3ERM=\n' +
                '-----END CERTIFICATE-----'
         
        }
    },
    { // ServerCertificate not found in getServerCertificate response
        ResponseMetadata: { RequestId: '1fc0aab6-e57c-4f05-9327-007419203c88' },
        ServerCertificate : {
            ServerCertificateMetadata: {
                Path: '/',
                ServerCertificateName: 'ExampleCertificate',
                ServerCertificateId: 'ASCAYE32SRU5Z4FTTGYXD',
                Arn: 'arn:aws:iam::560213429563:server-certificate/ExampleCertificate',
                UploadDate: '2020-08-13T11:37:27.000Z',
                Expiration: '2030-08-10T20:19:51.000Z'
            },
            CertificateBody: null
        },
    },
];

const createCache = (certificatesList, certificates) => {
    if (certificatesList.length) var serverCertificateName = certificatesList[0].ServerCertificateName;
    return {
        iam: {
            listServerCertificates: {
                'us-east-1': {
                    data: certificatesList
                },
            },
            getServerCertificate: {
                'us-east-1': {
                    [serverCertificateName]: {
                        data: certificates
                    }
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        iam: {
            listServerCertificates: {
                'us-east-1': {
                    err: {
                        message: 'error describing server certificates'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        iam: {
            listServerCertificates: {
                'us-east-1': null,
            },
        },
    };
};

describe('certificateMinimumSize', function () {
    describe('run', function () {

        // it('should PASS if unable to get server certificates', function (done) {
        //     const cache = createCache([]);
        //     certificateMinimumSize.run(cache, {}, (err, results) => {
        //         expect(results.length).to.equal(1);
        //         expect(results[0].status).to.equal(0);
        //         done();
        //     });
        // });

        // it('should not return any results if unable to get server certificates metadata list', function (done) {
        //     const cache = createNullCache();
        //     certificateMinimumSize.run(cache, {}, (err, results) => {
        //         expect(results.length).to.equal(0);
        //         done();
        //     });
        // });

        // it('should UNKNOWN if error occurs while fetching server certificates metadata list', function (done) {
        //     const cache = createErrorCache();
        //     certificateMinimumSize.run(cache, {}, (err, results) => {
        //         expect(results.length).to.equal(1);
        //         expect(results[0].status).to.equal(3);
        //         done();
        //     });
        // });

        // it('should UNKNOWN if unable to query for server certificate', function (done) {
        //     const cache = createCache([listCertificates[0]]);
        //     certificateMinimumSize.run(cache, {}, (err, results) => {
        //         expect(results.length).to.equal(1);
        //         expect(results[0].status).to.equal(3);
        //         done();
        //     });
        // });

        it('should UNKNOWN if unable to get server certificate body', function (done) {
            const cache = createCache([listCertificates[0]], certificates[2]);
            console.log(cache);
            certificateMinimumSize.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        // it('should PASS if server certificate has 2048 bit key length', function (done) {
        //     const cache = createCache([listCertificates[0]], certificates[0]);
        //     certificateMinimumSize.run(cache, {}, (err, results) => {
        //         expect(results.length).to.equal(1);
        //         expect(results[0].status).to.equal(0);
        //         done();
        //     });
        // });

        // it('should FAIL if server certificate has less than 2048 bit key length', function (done) {
        //     const cache = createCache([listCertificates[0]], certificates[1]);
        //     certificateMinimumSize.run(cache, {}, (err, results) => {
        //         expect(results.length).to.equal(1);
        //         expect(results[0].status).to.equal(2);
        //         done();
        //     });
        // });
    });
});