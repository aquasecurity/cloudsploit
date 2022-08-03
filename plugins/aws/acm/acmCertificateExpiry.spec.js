var expect = require('chai').expect;
var acmCertificateExpiry = require('./acmCertificateExpiry');

var cerExpiryWarn = new Date();
cerExpiryWarn.setMonth(cerExpiryWarn.getMonth() + 1);

var cerExpiryPass = new Date();
cerExpiryPass.setMonth(cerExpiryPass.getMonth() + 2);

var cerExpiryFail = new Date();
cerExpiryFail.setMonth(cerExpiryFail.getMonth() + 1);

var cerExpired = new Date();
cerExpired.setMonth(cerExpired.getMonth() - 1);

const listCertificates = [
    {
        "CertificateArn": "arn:aws:acm:us-east-1:000011112222:certificate/a59bf6c5-faba-4e45-8b20-054d90e41500",
        "DomainName": "www.xyz.com"
    }
];

const describeCertificate = [
    {
        "Certificate": {
            "CertificateArn": "arn:aws:acm:us-east-1:000011112222:certificate/a59bf6c5-faba-4e45-8b20-054d90e41500",
            "DomainName": "www.xyz.com",
            "Subject": "CN=www.xyz.com",
            "Issuer": "Amazon",
            "CreatedAt": "2021-10-05T08:56:23.000Z",
            "Status": "PENDING_VALIDATION",
            "KeyAlgorithm": "RSA-2048",
            "SignatureAlgorithm": "SHA256WITHRSA",
            "InUseBy": [],
            "Type": "AMAZON_ISSUED",
            "KeyUsages": [],
            "ExtendedKeyUsages": [],
            "RenewalEligibility": "ELIGIBLE",
            "NotAfter": cerExpiryPass,
            "Options": {
                "CertificateTransparencyLoggingPreference": "ENABLED"
            }
        }
    },
    {
        "Certificate": {
            "CertificateArn": "arn:aws:acm:us-east-1:000011112222:certificate/a59bf6c5-faba-4e45-8b20-054d90e41500",
            "DomainName": "www.xyz.com",
            "Subject": "CN=www.xyz.com",
            "Issuer": "Amazon",
            "CreatedAt": "2021-10-05T08:56:23.000Z",
            "Status": "PENDING_VALIDATION",
            "KeyAlgorithm": "RSA-2048",
            "SignatureAlgorithm": "SHA256WITHRSA",
            "InUseBy": [],
            "Type": "AMAZON_ISSUED",
            "KeyUsages": [],
            "ExtendedKeyUsages": [],
            "RenewalEligibility": "ELIGIBLE",
            "NotAfter": cerExpiryFail,
            "Options": {
                "CertificateTransparencyLoggingPreference": "ENABLED"
            }
        }
    },
    {
        "Certificate": {
            "CertificateArn": "arn:aws:acm:us-east-1:000011112222:certificate/a59bf6c5-faba-4e45-8b20-054d90e41500",
            "DomainName": "www.xyz.com",
            "Subject": "CN=www.xyz.com",
            "Issuer": "Amazon",
            "CreatedAt": "2021-10-05T08:56:23.000Z",
            "Status": "PENDING_VALIDATION",
            "KeyAlgorithm": "RSA-2048",
            "SignatureAlgorithm": "SHA256WITHRSA",
            "InUseBy": [],
            "Type": "AMAZON_ISSUED",
            "KeyUsages": [],
            "ExtendedKeyUsages": [],
            "RenewalEligibility": "ELIGIBLE",
            "NotAfter": cerExpired,
            "Options": {
                "CertificateTransparencyLoggingPreference": "ENABLED"
            }
        }
    },
    {
        "Certificate": {
            "CertificateArn": "arn:aws:acm:us-east-1:000011112222:certificate/a59bf6c5-faba-4e45-8b20-054d90e41500",
            "DomainName": "www.xyz.com",
            "Subject": "CN=www.xyz.com",
            "Issuer": "Amazon",
            "CreatedAt": "2021-10-05T08:56:23.000Z",
            "Status": "PENDING_VALIDATION",
            "KeyAlgorithm": "RSA-2048",
            "SignatureAlgorithm": "SHA256WITHRSA",
            "InUseBy": [],
            "Type": "AMAZON_ISSUED",
            "KeyUsages": [],
            "ExtendedKeyUsages": [],
            "RenewalEligibility": "ELIGIBLE",
            "NotAfter": cerExpiryWarn,
            "Options": {
                "CertificateTransparencyLoggingPreference": "ENABLED"
            }
        }
    },
    {
        "Certificate": {
            "CertificateArn": "arn:aws:acm:us-east-1:000011112222:certificate/a59bf6c5-faba-4e45-8b20-054d90e41500",
            "DomainName": "www.xyz.com",
            "Subject": "CN=www.xyz.com",
            "Issuer": "Amazon",
            "CreatedAt": "2021-10-05T08:56:23.000Z",
            "Status": "PENDING_VALIDATION",
            "KeyAlgorithm": "RSA-2048",
            "SignatureAlgorithm": "SHA256WITHRSA",
            "InUseBy": [],
            "Type": "AMAZON_ISSUED",
            "KeyUsages": [],
            "ExtendedKeyUsages": [],
            "RenewalEligibility": "INELIGIBLE",
            "Options": {
                "CertificateTransparencyLoggingPreference": "ENABLED"
            }
        }
    }
];

const createCache = (listData, listErr, describeData, describeErr) => {
    var certArn = (listData && listData.length) ? listData[0].CertificateArn : null;
    return {
        acm: {
            listCertificates: {
                'us-east-1': {
                    data: listData,
                    err: listErr
                },
            },
            describeCertificate: {
                'us-east-1': {
                    [certArn]: {
                        data: describeData,
                        err: describeErr
                    },
                },
            }
        },
    };
};

describe('acmCertificateExpiry', function () {
    describe('run', function () {
        it('should PASS if certificate expiration date exceeds set PASS number of days in the future', function (done) {
            const cache = createCache([listCertificates[0]], null, describeCertificate[0]);
            acmCertificateExpiry.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if certificate expiration date does not exceed set WARN number of days in the future', function (done) {
            const cache = createCache([listCertificates[0]], null, describeCertificate[1]);
            acmCertificateExpiry.run(cache, { acm_certificate_expiry_warn: '35' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if certificate has already expired', function (done) {
            const cache = createCache([listCertificates[0]], null, describeCertificate[2]);
            acmCertificateExpiry.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('expired');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should WARN if certificate expiration date exceed set WARN number of days in the future', function (done) {
            const cache = createCache([listCertificates[0]], null, describeCertificate[3]);
            acmCertificateExpiry.run(cache, { acm_certificate_expiry_warn: '25' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should WARN if certificate is not eligible for renewal', function (done) {
            const cache = createCache([listCertificates[0]], null, describeCertificate[4]);
            acmCertificateExpiry.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if No ACM certificates found', function (done) {
            const cache = createCache([]);
            acmCertificateExpiry.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list ACM certificates', function (done) {
            const cache = createCache(null, { message: 'err' });
            acmCertificateExpiry.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to describe ACM certificate', function (done) {
            const cache = createCache([listCertificates[0]], null, null, { message: 'err' });
            acmCertificateExpiry.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});