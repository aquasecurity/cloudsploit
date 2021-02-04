var expect = require('chai').expect;
const certificateExpiry = require('./certificateExpiry');

var certWarn = new Date();
certWarn.setMonth(certWarn.getMonth() + 1);
var certPass = new Date();
certPass.setMonth(certPass.getMonth() + 2);
var certFail = new Date();
certFail.setMonth(certFail.getMonth() - 1);

const listServerCertificates = [
    {
        "Path": "/",
        "ServerCertificateName": "ExampleCertificate",
        "ServerCertificateId": "ASCAYE32SRU5Z4FTTGYXD",
        "Arn": "arn:aws:iam::560213429563:server-certificate/ExampleCertificate",
        "UploadDate": "2020-08-13T11:37:27Z",
        "Expiration": certPass
    },
    {
        "Path": "/",
        "ServerCertificateName": "myServerCertificate",
        "ServerCertificateId": "ASCAYE32SRU5QZ74UU3W2",
        "Arn": "arn:aws:iam::560213429563:server-certificate/myServerCertificate",
        "UploadDate": "2020-08-15T15:16:31Z",
        "Expiration": certWarn
    },
    {
        "Path": "/",
        "ServerCertificateName": "myServerCertificate",
        "ServerCertificateId": "ASCAYE32SRU5QZ74UU3W2",
        "Arn": "arn:aws:iam::560213429563:server-certificate/myServerCertificate",
        "UploadDate": "2020-08-15T15:16:31Z",
        "Expiration": certFail
    }
];

const createCache = (report) => {
    return {
        iam:{
            listServerCertificates: {
                'us-east-1': {
                    data: report
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        iam:{
            listServerCertificates: {
                'us-east-1': {
                    err: {
                        message: 'error generating credential report'
                    },
                },
            }
        },
    };
};

const createNullCache = () => {
    return {
        iam:{
            listServerCertificates: {
                'us-east-1': null,
            },
        },
    };
};

describe('certificateExpiry', function () {
    describe('run', function () {
        it('should PASS if certificate expires in more than pass limit', function (done) {
            const cache = createCache([listServerCertificates[0]]);
            var settings = {
                certificate_expiry_pass: 45,
                certificate_expiry_warn: 30
            };
            certificateExpiry.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should WARN if certificate expires within the warn limit', function (done) {
            const cache = createCache([listServerCertificates[1]]);
            var settings = {
                certificate_expiry_pass: 45,
                certificate_expiry_warn: 25
            };
            certificateExpiry.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            });
        });

        it('should FAIL if certificate expires in less than warn limit', function (done) {
            const cache = createCache([listServerCertificates[1]]);
            var settings = {
                certificate_expiry_pass: 45,
                certificate_expiry_warn: 35
            };
            certificateExpiry.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if certificate expired already', function (done) {
            const cache = createCache([listServerCertificates[2]]);
            var settings = {
                certificate_expiry_pass: 45,
                certificate_expiry_warn: 30
            };
            certificateExpiry.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no certificates found', function (done) {
            const cache = createCache([]);
            certificateExpiry.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list server certificates', function (done) {
            const cache = createErrorCache();
            certificateExpiry.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list server certificates response not found', function (done) {
            const cache = createNullCache();
            certificateExpiry.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
