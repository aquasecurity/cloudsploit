var expect = require('chai').expect;
var acmSingleDomainNameCertificate = require('./acmSingleDomainNameCertificate');

const listCertificates = [
    {
        "CertificateArn": "arn:aws:acm:us-east-1:000011122222:certificate/4eb67297-7e64-4f9b-bfd1-38f962df491c",
        "DomainName": "CoolDude69.com"
    },
    {
        "CertificateArn": "arn:aws:acm:us-east-1:000011122222:certificate/8951d876-8417-4d5c-8caa-5f73a3b1211e",
        "DomainName": "*.viteace.com"
    }
];

const describeCertificate = [
    {
        "Certificate": {
            "CertificateArn": "arn:aws:acm:us-east-1:000011122222:certificate/4eb67297-7e64-4f9b-bfd1-38f962df491c",
            "DomainName": "cooldude69.com",
            "SubjectAlternativeNames": [
                "cooldude69.com"
            ],
            "DomainValidationOptions": [
                {
                    "DomainName": "cooldude69.com",
                    "ValidationDomain": "cooldude69.com",
                    "ValidationStatus": "PENDING_VALIDATION",
                    "ResourceRecord": {
                        "Name": "_fe4c0c0adae010605a723ccc178d8c77.cooldude69.com.",
                        "Type": "CNAME",
                        "Value": "_788985d4b083a63504b1d46c7db65abb.gbwdrhjxvn.acm-validations.aws."
                    },
                    "ValidationMethod": "DNS"
                }
            ],
            "Subject": "CN=cooldude69.com",
            "Issuer": "Amazon",
            "CreatedAt": "2022-03-09T17:39:31.095000+05:00",
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
    },
    {
        
    "Certificate": {
        "CertificateArn": "arn:aws:acm:us-east-1:000011122222:certificate/8951d876-8417-4d5c-8caa-5f73a3b1211e",
        "DomainName": "*.viteace.com",
        "SubjectAlternativeNames": [
            "*.viteace.com"
        ],
        "DomainValidationOptions": [
            {
                "DomainName": "*.viteace.com",
                "ValidationDomain": "*.viteace.com",
                "ValidationStatus": "PENDING_VALIDATION",
                "ResourceRecord": {
                    "Name": "_4f0a6aaf33ac9cc46e53f8ca0a6f9763.viteace.com.",
                    "Type": "CNAME",
                    "Value": "_2711d4a887c089c7518bfdb01655daf3.gbwdrhjxvn.acm-validations.aws."
                },
                "ValidationMethod": "DNS"
            }
        ],
        "Subject": "CN=*.viteace.com",
        "Issuer": "Amazon",
        "CreatedAt": "2022-03-09T17:58:27.078000+05:00",
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

describe('acmSingleDomainNameCertificate', function () {
    describe('run', function () {
        it('should PASS if ACM certificate is a single domain name certificate', function (done) {
            const cache = createCache([listCertificates[0]], null, describeCertificate[0]);
            acmSingleDomainNameCertificate.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('ACM certificate is a single domain name certificate')
                done();
            });
        });

        it('should FAIL if ACM certificate is a wildcard certificate', function (done) {
            const cache = createCache([listCertificates[0]], null, describeCertificate[1]);
            acmSingleDomainNameCertificate.run(cache, { acm_certificate_expiry_warn: '35' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('ACM certificate is a wildcard certificate')
                done();
            });
        });

        it('should PASS if No ACM certificates found', function (done) {
            const cache = createCache([]);
            acmSingleDomainNameCertificate.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No ACM certificates found')
                done();
            });
        });

        it('should UNKNOWN if unable to list ACM certificates', function (done) {
            const cache = createCache(null, { message: 'err' });
            acmSingleDomainNameCertificate.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to list ACM certificates')
                done();
            });
        });

        it('should UNKNOWN if unable to describe ACM certificate', function (done) {
            const cache = createCache([listCertificates[0]], null, null, { message: 'err' });
            acmSingleDomainNameCertificate.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to describe ACM certificate')
                done();
            });
        });
    });
});