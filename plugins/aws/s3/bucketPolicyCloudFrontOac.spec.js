var expect = require('chai').expect;
const bucketPolicyCloudFrontOac = require('./bucketPolicyCloudFrontOac');

const listBuckets = [
    {
        "Name": "testBucket",
        "CreationDate": "2021-01-10T13:45:10.000Z"
    },
    {
        "Name": "cdn-data",
        "CreationDate": "2020-11-30T10:43:10.000Z"
    },
    {
        "Name": "cdn-oai",
        "CreationDate": "2020-11-30T10:43:10.000Z"
    },
    {
        "Name": "cdn-oac",
        "CreationDate": "2020-11-30T10:43:10.000Z"
    },
    {
        "Name": "auto-test-label-policy",
        "CreationDate": "2021-01-10T13:45:10.000Z"
    }
];

const getBucketPolicy = [
    {
        "Policy": "{\"Version\":\"2008-10-17\",\"Id\":\"PolicyForCloudFrontPrivateContent\",\"Statement\":[{\"Sid\":\"AllowCloudFrontServicePrincipal\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudfront.amazonaws.com\"},\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::testBucket/*\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudfront::null:distribution/E154BVARTUU9DK\"}}}]}" 
    },
    {
        "Policy": "{\"Version\":\"2008-10-17\",\"Id\":\"PolicyForCloudFrontPrivateContent\",\"Statement\":[{\"Sid\":\"AllowCloudFrontServicePrincipal\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudfront.amazonaws.com\"},\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::testBucket/*\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":[\"arn:aws:cloudfront::null:distribution/E154BVARTUU9DK\",\"arn:aws:cloudfront::null:distribution/E2234BVARTUU9DK\"]}}},{\"Sid\":\"3\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E13LDJYTPM4UR5\"},\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::testBucket/*\"}]}"    },
    {
        "Policy": null
    },
    {
        "Policy": "{\"Version\":\"2008-10-17\",\"Id\":\"PolicyForCloudFrontPrivateContent\",\"Statement\":[{\"Sid\":\"1\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E1TWULNL6D9ZZY\"},\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::auto-test-label-policy/*\"},{\"Sid\":\"2\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E1PUAUTKXKHAMG\"},\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::auto-test-label-policy/*\"}]}"
    },
    {
        "Policy": "{\"Version\":\"2008-10-17\",\"Id\":\"PolicyForCloudFrontPrivateContent\",\"Statement\":[{\"Sid\":\"1\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E1TWULNL6D9ZZY\"},\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::auto-test-label-policy/*\"}]}"
    }
];

const listDistributions = [
    {
        "Id": "E154BVARTUU9DK",
        "ARN": "arn:aws:cloudfront::123456789:distribution/E154BVARTUU9DK",
        "Status": "Deployed",
        "LastModifiedTime": "2022-12-26T13:22:59.155000+00:00",
        "DomainName": "ditqwnuyq5wce.cloudfront.net",
        "Aliases": {
            "Quantity": 0
        },
        "Origins": {
            "Quantity": 2,
            "Items": [
                {
                    "Id": "testBucket.s3.us-east-1.amazonaws.com",
                    "DomainName": "testBucket.s3.us-east-1.amazonaws.com",
                    "OriginPath": "/hello.com",
                    "CustomHeaders": {
                        "Quantity": 0
                    },
                    "S3OriginConfig": {
                        "OriginAccessIdentity": ""
                    },
                    "ConnectionAttempts": 3,
                    "ConnectionTimeout": 10,
                    "OriginShield": {
                        "Enabled": false
                    },
                    "OriginAccessControlId": "E30EBFZ8ZXHG1P"
                }
            ]
        },
    },
    {
        "Id": "E16OS977N7ZR5X",
        "DomainName": "d1pu9fj4y91pww.cloudfront.net",
        "Aliases": {
            "Quantity": 0
        },
        "Origins": {
            "Quantity": 2,
            "Items": [
                {
                    "Id": "S3-my.bucket.aqua/cdn-1",
                    "DomainName": "my.bucket.aqua.s3.amazonaws.com",
                    "OriginPath": "/cdn-1",
                    "CustomHeaders": {
                        "Quantity": 0
                    },
                    "S3OriginConfig": {
                        "OriginAccessIdentity": ""
                    },
                    "ConnectionAttempts": 3,
                    "ConnectionTimeout": 10
                }
            ]
        }
    },
    {
        "Id": "E16OS977N77TVS",
        "DomainName": "d1pu9fj4y91pww.cloudfront.net",
        "Aliases": {
            "Quantity": 0
        },
        "Origins": {
            "Quantity": 2,
            "Items": [
                {
                    "Id": "S3-cdn-data/cdn-1",
                    "DomainName": "cdn-data.s3.amazonaws.com",
                    "OriginPath": "/cdn-1",
                    "CustomHeaders": {
                        "Quantity": 0
                    },
                    "S3OriginConfig": {
                        "OriginAccessIdentity": "origin-access-identity/cloudfront/E1GFXAXB2CIBLG"
                    },
                    "ConnectionAttempts": 3,
                    "ConnectionTimeout": 10
                }
            ]
        }
    },
    {
        "Id": "E16OS978FTE8VS",
        "DomainName": "d1pu9fj4y91pww.cloudfront.net",
        "Aliases": {
            "Quantity": 0
        },
        "Origins": {
            "Quantity": 2,
            "Items": [
                {
                    "Id": "S3-cdn-data/cdn-1",
                    "DomainName": "cdn-data.s3.amazonaws.com",
                    "OriginPath": "/cdn-1",
                    "CustomHeaders": {
                        "Quantity": 0
                    },
                    "S3OriginConfig": {
                        "OriginAccessIdentity": "origin-access-identity/cloudfront/E1GFXAXB2CIBLG"
                    },
                    "ConnectionAttempts": 3,
                    "ConnectionTimeout": 10
                }
            ]
        }
    },
    {
        "Id": "E18PKR761IFLYC",
        "ARN": "arn:aws:cloudfront::1234567:distribution/E18PKR761IFLYC",
        "Status": "InProgress",
        "LastModifiedTime": "2022-12-27T09:23:05.688000+00:00",
        "DomainName": "d27mad1q3ms1tu.cloudfront.net",
        "Aliases": {
            "Quantity": 0
        },
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "auto-test-label-policy.s3.us-east-1.amazonaws.com",
                    "DomainName": "auto-test-label-policy.s3.us-east-1.amazonaws.com",
                    "OriginPath": "/abc",
                    "CustomHeaders": {
                        "Quantity": 0
                    },
                    "S3OriginConfig": {
                        "OriginAccessIdentity": "origin-access-identity/cloudfront/E1PUAUTKXKHAMG"
                    },
                    "ConnectionAttempts": 3,
                    "ConnectionTimeout": 10,
                    "OriginShield": {
                        "Enabled": false
                    },
                    "OriginAccessControlId": ""
                }
            ]
        }
    },
    {
        "Id": "E18PKR761IFLYC",
                "ARN": "arn:aws:cloudfront::null:distribution/E18PKR761IFLYC",
                "Status": "Deployed",
                "LastModifiedTime": "2022-12-28T10:02:15.416000+00:00",
                "DomainName": "d27mad1q3ms1tu.cloudfront.net",
                "Aliases": {
                    "Quantity": 0
                },
                "Origins": {
                    "Quantity": 3,
                    "Items": [
                        {
                            "Id": "hahaauto-test-label-policy.s3.us-east-1.amazonaws.com",
                            "DomainName": "auto-test-label-policy.s3.us-east-1.amazonaws.com",
                            "OriginPath": "",
                            "CustomHeaders": {
                                "Quantity": 0
                            },
                            "S3OriginConfig": {
                                "OriginAccessIdentity": "origin-access-identity/cloudfront/E1PUAUTKXKHAMG"
                            },
                            "ConnectionAttempts": 3,
                            "ConnectionTimeout": 10,
                            "OriginShield": {
                                "Enabled": false
                            },
                            "OriginAccessControlId": ""
                        },
                        {
                            "Id": "abcauto-test-label-policy.s3.us-east-1.amazonaws.com",
                            "DomainName": "auto-test-label-policy.s3.us-east-1.amazonaws.com",
                            "OriginPath": "",
                            "CustomHeaders": {
                                "Quantity": 0
                            },
                            "S3OriginConfig": {
                                "OriginAccessIdentity": ""
                            },
                            "ConnectionAttempts": 3,
                            "ConnectionTimeout": 10,
                            "OriginShield": {
                                "Enabled": false
                            },
                            "OriginAccessControlId": "E1LC09HCRJUH5H"
                        },
                        {
                            "Id": "auto-test-label-policy.s3.us-east-1.amazonaws.com",
                            "DomainName": "auto-test-label-policy.s3.us-east-1.amazonaws.com",
                            "OriginPath": "/abc",
                            "CustomHeaders": {
                                "Quantity": 0
                            },
                            "S3OriginConfig": {
                                "OriginAccessIdentity": "origin-access-identity/cloudfront/E1PUAUTKXKHAMG"
                            },
                            "ConnectionAttempts": 3,
                            "ConnectionTimeout": 10,
                            "OriginShield": {
                                "Enabled": false
                            },
                            "OriginAccessControlId": ""
                        }
                    ]
                },
                "OriginGroups": {
                    "Quantity": 0
                }
    }
];

const createCache = (listDistributions, listBuckets, getBucketPolicy, policyErr) => {
    var bucketName = (listBuckets && listBuckets.length) ? listBuckets[0].Name : null;
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: listBuckets
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    [bucketName]: {
                        err: policyErr,
                        data: getBucketPolicy
                    },
                },
            },
            getBucketLocation: {
                'us-east-1': {
                    [bucketName]: {
                        data: {
                            LocationConstraint: 'us-east-1'
                        }
                    }
                }
            }
        },
        cloudfront: {
            listDistributions: {
                'us-east-1': {
                    data: listDistributions
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    err: {
                        message: 'error while listing S3 buckets'
                    },
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    err: {
                        message: 'error while getting bucket logging'
                    },
                },
            },
        },
        cloudfront: {
            listDistributions: {
                'us-east-1': {
                    err: {
                        message: 'Unable to list distributions'
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        cloudfront: {
            listDistributions: {
                'us-east-1': null
            }
        }
    };
};

describe('bucketPolicyCloudFrontOac', function () {
    describe('run', function () {
        it('should PASS if no S3 origins found for CloudFront distributions', function (done) {
            const cache = createCache([listDistributions[1]]);
            bucketPolicyCloudFrontOac.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No S3 origins found for CloudFront distributions');
                done();
            });
        });

        it('should PASS if S3 bucket is origin to only one CloudFront distribution', function (done) {
            const cache = createCache([listDistributions[0]], [listBuckets[0]], getBucketPolicy[0]);
            bucketPolicyCloudFrontOac.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('S3 bucket is origin to only one CloudFront distribution')
                done();
            });
        });

        it('should FAIL if S3 bucket is origin to more than one distributions', function (done) {
            const cache = createCache([listDistributions[2], listDistributions[3]], [listBuckets[1]]);
            bucketPolicyCloudFrontOac.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('S3 bucket is origin to more than one distributions');
                done();
            });
        });

        it('should FAIL if S3 bucket is origin to distribution without an Origin Access Control', function (done) {
            const cache = createCache([listDistributions[4]],[listBuckets[0]],getBucketPolicy[3]);
            bucketPolicyCloudFrontOac.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('without an Origin Access Control');
                done();
            });
        });

        it('should FAIL if S3 bucket is origin to distribution and allows access to unknown sources', function (done) {
            const cache = createCache([listDistributions[0]], [listBuckets[0]], getBucketPolicy[1]);
            bucketPolicyCloudFrontOac.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('allows access to these unknown sources');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

       it('should FAIL if S3 bucket is origin to distribution and does not allow access to these CloudFront origins', function (done) {
            const cache = createCache([listDistributions[5]], [listBuckets[4]], getBucketPolicy[4]);
            bucketPolicyCloudFrontOac.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('does not allow access to these CloudFront origins')
                done();
            });
        });

        it('should FAIL if no bucket policy found for S3 bucket', function (done) {
            const cache = createCache([listDistributions[0]], [listBuckets[0]], getBucketPolicy[2], { code: 'NoSuchBucketPolicy' });
            bucketPolicyCloudFrontOac.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No bucket policy found for S3 bucket');
                done();
            });
        });

        it('should PASS if no S3 origins to check', function (done) {
            const cache = createCache([]);
            bucketPolicyCloudFrontOac.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list CloudFront distributions', function (done) {
            const cache = createErrorCache();
            bucketPolicyCloudFrontOac.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any result if list distributions result not found', function (done) {
            const cache = createNullCache();
            bucketPolicyCloudFrontOac.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});