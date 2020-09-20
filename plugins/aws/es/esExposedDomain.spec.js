const expect = require('chai').expect;
const esExposedDomain = require('./esExposedDomain');

const domainNames = [
    {
        "DomainName": "test-domain3-104"
    },
    {
        "DomainName": "test-domain-104"
    },
    {
        "DomainName": "test-domain2-104"
    }
];

const domains = [
    {
        "DomainStatus": {
            "DomainId": "1123456654321/test-domain-104",
            "DomainName": "test-domain-104",
            "ARN": "arn:aws:es:us-east-1:1123456654321:domain/test-domain-104",
            "Created": true,
            "Deleted": false,
            "Endpoints": {
                "vpc": "vpc-test-domain-104-cpdukg4kpajspjci6szlymbqvi.us-east-1.es.amazonaws.com"
            },
            "Processing": false,
            "UpgradeProcessing": false,
            "ElasticsearchVersion": "7.7",
            "ElasticsearchClusterConfig": {
                "InstanceType": "t2.small.elasticsearch",
                "InstanceCount": 1,
                "DedicatedMasterEnabled": false,
                "ZoneAwarenessEnabled": false,
                "WarmEnabled": false
            },
            "EBSOptions": {
                "EBSEnabled": true,
                "VolumeType": "gp2",
                "VolumeSize": 10
            },
            "AccessPolicies": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"es:*\",\"Resource\":\"arn:aws:es:us-east-1:1123456654321:domain/test-domain-104/*\"}]}",
            "SnapshotOptions": {},
            "VPCOptions": {
                "VPCId": "vpc-99de2fe4",
                "SubnetIds": [
                    "subnet-c21b84cc"
                ],
                "AvailabilityZones": [
                    "us-east-1f"
                ],
                "SecurityGroupIds": [
                    "sg-047e6cc36b13ec60e"
                ]
            },
            "CognitoOptions": {
                "Enabled": false
            },
            "EncryptionAtRestOptions": {
                "Enabled": false
            },
            "NodeToNodeEncryptionOptions": {
                "Enabled": false
            },
            "AdvancedOptions": {
                "rest.action.multi.allow_explicit_index": "true"
            },
            "ServiceSoftwareOptions": {
                "CurrentVersion": "R20200721",
                "NewVersion": "",
                "UpdateAvailable": false,
                "Cancellable": false,
                "UpdateStatus": "COMPLETED",
                "Description": "There is no software update available for this domain.",
                "AutomatedUpdateDate": 0.0,
                "OptionalDeployment": true
            },
            "DomainEndpointOptions": {
                "EnforceHTTPS": false,
                "TLSSecurityPolicy": "Policy-Min-TLS-1-0-2019-07"
            },
            "AdvancedSecurityOptions": {
                "Enabled": false,
                "InternalUserDatabaseEnabled": false
            }
        }
    },
    {
        "DomainStatus": {
            "DomainId": "1123456654321/test-domain3-104",
            "DomainName": "test-domain3-104",
            "ARN": "arn:aws:es:us-east-1:1123456654321:domain/test-domain3-104",
            "Created": true,
            "Deleted": false,
            "Endpoint": "search-test-domain3-104-oqrea5hh2cok7twvowby43f3iy.us-east-1.es.amazonaws.com",
            "Processing": false,
            "UpgradeProcessing": false,
            "ElasticsearchVersion": "7.7",
            "ElasticsearchClusterConfig": {
                "InstanceType": "t2.small.elasticsearch",
                "InstanceCount": 1,
                "DedicatedMasterEnabled": false,
                "ZoneAwarenessEnabled": false,
                "WarmEnabled": false
            },
            "EBSOptions": {
                "EBSEnabled": true,
                "VolumeType": "gp2",
                "VolumeSize": 10
            },
            "SnapshotOptions": {},
            "CognitoOptions": {
                "Enabled": false
            },
            "EncryptionAtRestOptions": {
                "Enabled": false
            },
            "NodeToNodeEncryptionOptions": {
                "Enabled": false
            },
            "AdvancedOptions": {
                "rest.action.multi.allow_explicit_index": "true"
            },
            "ServiceSoftwareOptions": {
                "CurrentVersion": "R20200721",
                "NewVersion": "",
                "UpdateAvailable": false,
                "Cancellable": false,
                "UpdateStatus": "COMPLETED",
                "Description": "There is no software update available for this domain.",
                "AutomatedUpdateDate": 0.0,
                "OptionalDeployment": true
            },
            "DomainEndpointOptions": {
                "EnforceHTTPS": false,
                "TLSSecurityPolicy": "Policy-Min-TLS-1-0-2019-07"
            },
            "AdvancedSecurityOptions": {
                "Enabled": false,
                "InternalUserDatabaseEnabled": false
            }
        }
    },
    {
        "DomainStatus": {
            "DomainId": "1123456654321/test-domain2-104",
            "DomainName": "test-domain2-104",
            "ARN": "arn:aws:es:us-east-1:1123456654321:domain/test-domain2-104",
            "Created": true,
            "Deleted": false,
            "Endpoints": {
                "vpc": "vpc-test-domain2-104-zekicf2qfhcvve2x4letx66rcm.us-east-1.es.amazonaws.com"
            },
            "Processing": false,
            "UpgradeProcessing": false,
            "ElasticsearchVersion": "7.7",
            "ElasticsearchClusterConfig": {
                "InstanceType": "t2.small.elasticsearch",
                "InstanceCount": 1,
                "DedicatedMasterEnabled": false,
                "ZoneAwarenessEnabled": false,
                "WarmEnabled": false
            },
            "EBSOptions": {
                "EBSEnabled": true,
                "VolumeType": "gp2",
                "VolumeSize": 10
            },
            "AccessPolicies": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::1123456654321:role/service-role/AmazonComprehendServiceRole-akhtar-comprehend-role\"},\"Action\":\"es:*\",\"Resource\":\"arn:aws:es:us-east-1:1123456654321:domain/test-domain2-104/*\"}]}",
            "SnapshotOptions": {},
            "VPCOptions": {
                "VPCId": "vpc-99de2fe4",
                "SubnetIds": [
                    "subnet-6a8b635b"
                ],
                "AvailabilityZones": [
                    "us-east-1e"
                ],
                "SecurityGroupIds": [
                    "sg-001639e564442dfec"
                ]
            },
            "CognitoOptions": {
                "Enabled": false
            },
            "EncryptionAtRestOptions": {
                "Enabled": false
            },
            "NodeToNodeEncryptionOptions": {
                "Enabled": false
            },
            "AdvancedOptions": {
                "rest.action.multi.allow_explicit_index": "true"
            },
            "ServiceSoftwareOptions": {
                "CurrentVersion": "R20200721",
                "NewVersion": "",
                "UpdateAvailable": false,
                "Cancellable": false,
                "UpdateStatus": "COMPLETED",
                "Description": "There is no software update available for this domain.",
                "AutomatedUpdateDate": 0.0,
                "OptionalDeployment": true
            },
            "DomainEndpointOptions": {
                "EnforceHTTPS": false,
                "TLSSecurityPolicy": "Policy-Min-TLS-1-0-2019-07"
            },
            "AdvancedSecurityOptions": {
                "Enabled": false,
                "InternalUserDatabaseEnabled": false
            }
        }
    }
];

const createCache = (domainNames, domains) => {
    if (domainNames && domainNames.length) var name = domainNames[0].DomainName;
    return {
        es: {
            listDomainNames: {
                'us-east-1': {
                    data: domainNames,
                },
            },
            describeElasticsearchDomain: {
                'us-east-1': {
                    [name]: {
                        data: domains
                    }
                }
            }
        },
    };
};

const createErrorCache = () => {
    return {
        es: {
            listDomainNames: {
                'us-east-1': {
                    err: {
                        message: 'error listing domain names'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        es: {
            listDomainNames: {
                'us-east-1': null,
            },
        },
    };
};

describe('esExposedDomain', function () {
    describe('run', function () {
        it('should FAIL if domain is exposed to all AWS accounts', function (done) {
            const cache = createCache([domainNames[1]], domains[0]);
            esExposedDomain.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if domain is not exposed to all AWS accounts', function (done) {
            const cache = createCache([domainNames[1]], domains[2]);
            esExposedDomain.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if no access policy found', function (done) {
            const cache = createCache([domainNames[2]], domains[2]);
            esExposedDomain.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no domain names found', function (done) {
            const cache = createCache([]);
            esExposedDomain.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there was an error listing domain names', function (done) {
            const cache = createErrorCache();
            esExposedDomain.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for domain names', function (done) {
            const cache = createNullCache();
            esExposedDomain.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
